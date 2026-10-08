"""Unit tests for rs9.rpm_lint: structured evidence, parsing, sanitization, and cleanliness."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9.build_native import CommandReceipt, MockCommandRunner
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.scratch import canonical
from rs9.rpm_lint import (
    MAX_FINDINGS,
    MAX_MESSAGE_CHARS,
    MAX_STREAM_BYTES,
    RPMLINT_EVIDENCE_SCHEMA,
    build_rpmlint_evidence,
    evaluate_rpmlint_cleanliness,
    execute_rpmlint,
    parse_rpmlint_output,
    sanitize_text,
)


class RpmLintParserTests(unittest.TestCase):
    def test_unknown_rpmlint_prefixed_line_is_not_a_header(self):
        parsed = parse_rpmlint_output(
            'rpmlint: unexpected failure reading inputs\n'
            '1 packages and 1 specfiles checked; 0 errors, 0 warnings.\n', strict=False)
        self.assertFalse(parsed['parse_complete'])
        self.assertEqual(parsed['unparsed_count'], 1)

    def test_upstream_2x_decorated_session_and_group_counts_fixture(self):
        # Synthetic fixture of upstream Lint._print_header/_run formatting.
        output=('==== rpmlint session starts ====\nrpmlint: 2.6.0\nconfiguration:\n'
                '    /usr/lib/python3.14/site-packages/rpmlint/configdefaults.toml\n'
                '    /etc/xdg/rpmlint/fedora.toml\nchecks: 32, packages: 2\n'
                'pkg.x86_64: E: binary-check /usr/lib/theme-forge-stellar-burst/bin/x\n'
                'pkg.x86_64: E: binary-check /tmp/private-fixture/file\n'
                'pkg.spec:10: W: metadata-check warning\n'
                '==== 1 packages and 1 specfiles checked; 2 errors, 1 warnings, 0 filtered, 2 badness; has taken 0.1 s ====\n')
        parsed=parse_rpmlint_output(output,64)
        self.assertTrue(parsed['parse_complete'])
        self.assertEqual(parsed['groups'][0]['count'],2)
        self.assertEqual(parsed['groups'][0]['code'],'binary-check')
        self.assertNotIn('private-fixture',json.dumps(parsed))
        self.assertIn('package:usr/lib/theme-forge-',json.dumps(parsed))

    def test_warning_only_zero_exit_keeps_warning_semantics(self):
        self.assertTrue(evaluate_rpmlint_cleanliness({'errors':0,'warnings':1},0)[0])
        for exit_code in (64,65,66,2):
            self.assertFalse(evaluate_rpmlint_cleanliness({'errors':0,'warnings':1},exit_code)[0])
    def test_parse_clean_rpmlint_output(self):
        output = (
            "rpmlint (Fedora 43)\n"
            "Loaded configuration from /etc/rpmlint/fedora.toml\n"
            "0 packages and 1 specfiles checked; 0 errors, 0 warnings, 0 filtered.\n"
        )
        parsed = parse_rpmlint_output(output, exit_code=0)
        self.assertEqual(len(parsed["findings"]), 0)
        self.assertFalse(parsed["findings_truncated"])
        self.assertEqual(parsed["summary"]["packages"], 0)
        self.assertEqual(parsed["summary"]["specfiles"], 1)
        self.assertEqual(parsed["summary"]["errors"], 0)
        self.assertEqual(parsed["summary"]["warnings"], 0)
        self.assertEqual(parsed["summary"]["filtered"], 0)
        self.assertEqual(len(parsed["session_headers"]), 2)
        self.assertIn("rpmlint (Fedora 43)", parsed["session_headers"][0])

    def test_parse_rpmlint_findings_levels(self):
        output = (
            "theme-forge-stellar-loom.noarch: E: explicit-lib-dependency nodejs\n"
            "theme-forge-stellar-loom.spec:12: W: non-standard-group Development/Tools\n"
            "theme-forge-stellar-burst.x86_64: I: binary-or-shlib-defines-rpath /usr/lib\n"
            "1 packages and 1 specfiles checked; 1 errors, 1 warnings, 0 filtered.\n"
        )
        parsed = parse_rpmlint_output(output, exit_code=1)
        findings = parsed["findings"]
        self.assertEqual(len(findings), 3)

        e_finding = findings[0]
        self.assertEqual(e_finding["target"], "theme-forge-stellar-loom.noarch")
        self.assertEqual(e_finding["level"], "E")
        self.assertEqual(e_finding["check"], "explicit-lib-dependency")
        self.assertEqual(e_finding["message"], "nodejs")

        w_finding = findings[1]
        self.assertEqual(w_finding["target"], "theme-forge-stellar-loom.spec")
        self.assertEqual(w_finding["line"], 12)
        self.assertEqual(w_finding["level"], "W")
        self.assertEqual(w_finding["check"], "non-standard-group")

        i_finding = findings[2]
        self.assertEqual(i_finding["target"], "theme-forge-stellar-burst.x86_64")
        self.assertEqual(i_finding["level"], "I")
        self.assertEqual(i_finding["check"], "binary-or-shlib-defines-rpath")

    def test_bracketed_and_verbose_levels(self):
        output = (
            "theme-forge-stellar-loom.noarch: [E]: invalid-license GPLv3\n"
            "theme-forge-stellar-loom.spec: WARNING: no-%clean-section\n"
            "0 packages and 1 specfiles checked; 1 errors, 1 warnings, 0 filtered.\n"
        )
        parsed = parse_rpmlint_output(output, exit_code=1)
        self.assertEqual(parsed["findings"][0]["level"], "E")
        self.assertEqual(parsed["findings"][1]["level"], "W")

    def test_empty_output_fails_closed(self):
        for raw in ("", "   \n\t\n  "):
            with self.subTest(raw=raw), self.assertRaises(ContractError) as caught:
                parse_rpmlint_output(raw)
            self.assertEqual(caught.exception.code, "RPMLINT_FAILED")
            self.assertEqual(caught.exception.details.get("reason_token"), "empty-output")

    def test_missing_summary_line_fails_closed(self):
        output = "theme-forge-stellar-loom.noarch: E: explicit-lib-dependency nodejs\n"
        with self.assertRaises(ContractError) as caught:
            parse_rpmlint_output(output)
        self.assertEqual(caught.exception.code, "RPMLINT_FAILED")
        self.assertEqual(caught.exception.details.get("reason_token"), "malformed-output")

    def test_unparseable_line_fails_closed(self):
        output = (
            "Random unparseable garbage output\n"
            "0 packages and 1 specfiles checked; 0 errors, 0 warnings, 0 filtered.\n"
        )
        with self.assertRaises(ContractError) as caught:
            parse_rpmlint_output(output)
        self.assertEqual(caught.exception.code, "RPMLINT_FAILED")
        self.assertEqual(caught.exception.details.get("reason_token"), "malformed-output")
        self.assertEqual(caught.exception.parsed['unparsed_samples'][0]['sample'],
                         'Random unparseable garbage output')

    def test_error_count_mismatch_fails_closed(self):
        # Summary claims 2 errors, but parsed findings have only 1
        output = (
            "theme-forge-stellar-loom.noarch: E: explicit-lib-dependency nodejs\n"
            "1 packages and 0 specfiles checked; 2 errors, 0 warnings, 0 filtered.\n"
        )
        with self.assertRaises(ContractError) as caught:
            parse_rpmlint_output(output)
        self.assertEqual(caught.exception.code, "RPMLINT_FAILED")
        self.assertEqual(caught.exception.details.get("reason_token"), "count-mismatch")

    def test_warning_count_mismatch_fails_closed(self):
        # Summary claims 3 warnings, but parsed findings have only 1
        output = (
            "theme-forge-stellar-loom.noarch: W: summary-not-capitalized\n"
            "1 packages and 0 specfiles checked; 0 errors, 3 warnings, 0 filtered.\n"
        )
        with self.assertRaises(ContractError) as caught:
            parse_rpmlint_output(output)
        self.assertEqual(caught.exception.code, "RPMLINT_FAILED")
        self.assertEqual(caught.exception.details.get("reason_token"), "count-mismatch")

    def test_exit_code_and_warning_error_semantics(self):
        summary_clean = {"packages": 1, "specfiles": 1, "errors": 0, "warnings": 0, "filtered": 0}
        summary_warnings = {"packages": 1, "specfiles": 1, "errors": 0, "warnings": 2, "filtered": 0}
        summary_errors = {"packages": 1, "specfiles": 1, "errors": 1, "warnings": 0, "filtered": 0}

        # 1. Clean exit 0 with 0 errors, 0 warnings -> clean
        clean, reason = evaluate_rpmlint_cleanliness(summary_clean, exit_code=0)
        self.assertTrue(clean)
        self.assertEqual(reason, "clean")

        # 2. Exit 64 with warnings -> NOT clean, fails closed (never green exit64)
        clean, reason = evaluate_rpmlint_cleanliness(summary_warnings, exit_code=64)
        self.assertFalse(clean)
        self.assertEqual(reason, "lint-exit64")

        # 3. Exit 0 with errors -> NOT clean
        clean, reason = evaluate_rpmlint_cleanliness(summary_errors, exit_code=0)
        self.assertFalse(clean)
        self.assertEqual(reason, "lint-errors")

        # 4. Exit 1 with errors -> NOT clean
        clean, reason = evaluate_rpmlint_cleanliness(summary_errors, exit_code=1)
        self.assertFalse(clean)
        self.assertEqual(reason, "lint-errors")

        # 5. Exit 1 with 0 errors -> NOT clean
        clean, reason = evaluate_rpmlint_cleanliness(summary_clean, exit_code=1)
        self.assertFalse(clean)
        self.assertEqual(reason, "exit-nonzero")


class RpmLintSanitizationTests(unittest.TestCase):
    def test_sanitize_private_host_paths(self):
        text = "error: file /tmp/fixture/SPECS/loom.spec line 4: invalid"
        sanitized = sanitize_text(text)
        self.assertNotIn("/tmp/fixture", sanitized)
        self.assertIn("[PATH]", sanitized)

        tmp_text = "Checking /tmp/scratch_1234/theme-forge-stellar-burst.rpm: NOKEY"
        sanitized_tmp = sanitize_text(tmp_text)
        self.assertNotIn("/tmp/scratch_1234", sanitized_tmp)
        self.assertIn("[PATH]", sanitized_tmp)

    def test_sanitize_credentials(self):
        text = "Warning: token " + "ghp_" + "X"*36 + " found in payload"
        sanitized = sanitize_text(text)
        self.assertNotIn("ghp_", sanitized)
        self.assertIn("[REDACTED_CREDENTIAL]", sanitized)

        pat_text = "github_pat_" + "X"*82
        self.assertIn("[REDACTED_CREDENTIAL]", sanitize_text(pat_text))

        aws_text = "Access key " + "AKIA" + "X"*16 + " observed"
        self.assertIn("[REDACTED_CREDENTIAL]", sanitize_text(aws_text))

    def test_sanitize_control_bytes_and_ansi(self):
        colored = "\x1b[31;1mError:\x1b[0m explicit-lib-dependency \x00\x07bell\x1b[0m"
        sanitized = sanitize_text(colored)
        self.assertNotIn("\x1b[", sanitized)
        self.assertNotIn("\x00", sanitized)
        self.assertNotIn("\x07", sanitized)
        self.assertEqual(sanitized, "[NONPRINTABLE]")

    def test_target_sanitization(self):
        raw_spec = "/tmp/rpmbuild/SPECS/theme-forge-stellar-loom.spec:10: E: test-check"
        raw = raw_spec + "\n0 packages and 1 specfiles checked; 1 errors, 0 warnings, 0 filtered.\n"
        parsed = parse_rpmlint_output(raw)
        self.assertEqual(parsed["findings"][0]["target"], "theme-forge-stellar-loom.spec")

    def test_bounded_findings_and_message_capping(self):
        long_msg = "x" * 1000
        sanitized = sanitize_text(long_msg, max_chars=MAX_MESSAGE_CHARS)
        self.assertLessEqual(len(sanitized), MAX_MESSAGE_CHARS + 3)

        # Output with more than MAX_FINDINGS findings
        lines = [f"pkg.noarch: W: warning-{i} msg" for i in range(120)]
        lines.append(f"1 packages and 0 specfiles checked; 0 errors, 120 warnings, 0 filtered.\n")
        parsed = parse_rpmlint_output("\n".join(lines))
        self.assertEqual(len(parsed["findings"]), MAX_FINDINGS)
        self.assertTrue(parsed["findings_truncated"])


class RpmLintExecutionAndEvidenceTests(unittest.TestCase):
    def test_candidate_requires_one_package_and_one_spec(self):
        for packages, specs in ((0, 0), (0, 1), (1, 0), (2, 1), (1, 2)):
            with self.subTest(packages=packages, specs=specs):
                receipt = CommandReceipt(['rpmlint'], 0,
                    f'{packages} packages and {specs} specfiles checked; 0 errors, 0 warnings.\n'.encode(), b'')
                evidence = build_rpmlint_evidence(receipt, self.spec, self.rpm, 'test')
                self.assertFalse(evidence['clean'])
                self.assertEqual(evidence['reason_token'], 'input-count-mismatch')

    def test_evidence_bound_failure_keeps_quarantine_identity(self):
        runner = MockCommandRunner(available_tools={'rpmlint': '/usr/bin/rpmlint'},
            handlers={'rpmlint': lambda argv, **kw: CommandReceipt(argv, 0,
                b'1 packages and 1 specfiles checked; 0 errors, 0 warnings.\n', b'')})
        with patch('rs9.rpm_lint.canonical', return_value=b'x' * (60 * 1024 + 1)):
            with self.assertRaises(ContractError) as caught:
                execute_rpmlint(runner, self.spec, self.rpm, 'test', cwd=self.root)
        self.assertEqual(caught.exception.package_path, str(self.rpm))
        self.assertEqual(caught.exception.spec_path, str(self.spec))
        self.assertEqual(caught.exception.package_sha256, digest(self.rpm.read_bytes()))

    def test_collection_failure_with_missing_input_keeps_lint_receipt(self):
        for missing_name in ("rpm", "spec"):
            with self.subTest(missing=missing_name):
                self.rpm.write_bytes(b"synthetic-rpm-bytes")
                self.spec.write_bytes(b"Name: test\nVersion: 1.0.0\n")
                missing = getattr(self, missing_name)

                def handler(argv, **kwargs):
                    if "--version" not in argv:
                        missing.unlink()
                    return CommandReceipt(argv, 64, b"lint-output\n", b"lint-error\n")

                runner = MockCommandRunner(available_tools={"rpmlint": "/usr/bin/rpmlint"},
                                           handlers={"rpmlint": handler})
                with patch("rs9.rpm_lint.canonical", return_value=b"x" * (60 * 1024 + 1)):
                    with self.assertRaises(ContractError) as caught:
                        execute_rpmlint(runner, self.spec, self.rpm, "test", cwd=self.root)
                error = caught.exception
                self.assertEqual(error.code, "RPMLINT_FAILED")
                self.assertEqual(error.details["exit_code"], 64)
                self.assertEqual(error.details["stdout_sha256"], digest(b"lint-output\n"))
                self.assertEqual(error.details["stderr_sha256"], digest(b"lint-error\n"))
                self.assertEqual(error.package_path, str(self.rpm))
                self.assertEqual(error.spec_path, str(self.spec))
                for name, path in (("package", self.rpm), ("spec", self.spec)):
                    expected = "" if path == missing else digest(path.read_bytes())
                    self.assertEqual(getattr(error, name + "_sha256"), expected)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.spec = self.root / "test.spec"
        self.spec.write_bytes(b"Name: test\nVersion: 1.0.0\n")
        self.rpm = self.root / "test-1.0.0-1.fc43.noarch.rpm"
        self.rpm.write_bytes(b"synthetic-rpm-bytes")

    def test_tool_version_query_failure_does_not_replace_blamed_lint_receipt(self):
        def handler(argv, cwd=None, env=None):
            if "--version" in argv:
                # Version query fails
                return CommandReceipt(argv, 127, b"", b"rpmlint: command not found\n")
            # Lint runs and fails with error
            return CommandReceipt(
                argv,
                1,
                b"test.noarch: E: explicit-lib-dependency nodejs\n1 packages and 1 specfiles checked; 1 errors, 0 warnings, 0 filtered.\n",
                b"",
            )

        runner = MockCommandRunner(
            available_tools={"rpmlint": "/usr/bin/rpmlint"},
            handlers={"rpmlint": handler},
        )

        with self.assertRaises(ContractError) as caught:
            execute_rpmlint(runner, self.spec, self.rpm, "test")

        self.assertEqual(caught.exception.code, "RPMLINT_FAILED")
        self.assertEqual(caught.exception.details["diagnostic_token"], "explicit-lib-dependency")
        self.assertEqual(caught.exception.details["reason_token"], "lint-errors")
        self.assertEqual(caught.exception.details["exit_code"], 1)
        # Blamed lint receipt was preserved, not replaced by version failure
        self.assertEqual(caught.exception.evidence["tool_version"]["version"], "query-failed")

    def test_malformed_output_preserves_findings_and_writes_bounded_evidence(self):
        for raw in (b'', b'pkg.noarch: E: real-code detail\nunexpected output\n'):
            runner=MockCommandRunner(available_tools={'rpmlint':'/usr/bin/rpmlint'},
                handlers={'rpmlint':lambda argv,**kw:CommandReceipt(argv,64,raw,b'')})
            with self.assertRaises(ContractError) as caught:
                execute_rpmlint(runner,self.spec,self.rpm,'fixture',cwd=self.root)
            evidence=caught.exception.evidence
            self.assertFalse(evidence['parse_complete'])
            self.assertFalse(evidence['clean'])
            retained=json.loads((self.root/'rpmlint-findings.json').read_bytes())
            self.assertEqual(retained,evidence)
            self.assertLessEqual(len(json.dumps(retained)),64*1024)
            if raw:
                self.assertEqual(evidence['groups'][0]['code'],'real-code')
                self.assertEqual(evidence['unparsed_count'],1)
                self.assertEqual(evidence['findings_summary']['errors'],1)

    def test_version_credentials_are_sanitized_before_text_is_capped(self):
        token = 'ghp_' + 'X' * 36
        malformed = parse_rpmlint_output('/tmp/private-fixture/file ' + token, strict=False)
        self.assertNotIn('private-fixture', json.dumps(malformed))
        self.assertNotIn('ghp_', json.dumps(malformed))
        self.assertEqual(malformed['unparsed_samples'][0]['sample'], '[CREDENTIAL_STREAM_WITHHELD]')
        def handler(argv, **kwargs):
            output = ('x' * 100 + token).encode() if '--version' in argv else (
                b'1 packages and 1 specfiles checked; 0 errors, 0 warnings.\n')
            return CommandReceipt(argv, 0, output, b'')
        runner = MockCommandRunner(available_tools={'rpmlint': '/usr/bin/rpmlint'},
                                   handlers={'rpmlint': handler})
        evidence, _ = execute_rpmlint(runner, self.spec, self.rpm, 'test', cwd=self.root)
        self.assertNotIn('ghp_', json.dumps(evidence))

    def test_evidence_preserves_four_field_identity_and_payload_hash(self):
        def handler(argv, cwd=None, env=None):
            if "--version" in argv:
                return CommandReceipt(argv, 0, b"rpmlint version 2.5.0\n", b"")
            return CommandReceipt(
                argv,
                0,
                b"1 packages and 1 specfiles checked; 0 errors, 0 warnings, 0 filtered.\n",
                b"",
            )

        runner = MockCommandRunner(
            available_tools={"rpmlint": "/usr/bin/rpmlint"},
            handlers={"rpmlint": handler},
        )

        identity = {"name": "test", "version": "1.0.0", "release": "1.fc43", "arch": "noarch"}
        payload = {"tag": "PAYLOADSHA256", "algo_tag": "PAYLOADSHA256ALGO",
                   "payload_digest": "a" * 64, "payload_digest_algo": "sha256"}

        evidence, receipts = execute_rpmlint(
            runner, self.spec, self.rpm, "test",
            rpm_identity=identity, rpm_payload_digest=payload,
        )

        self.assertEqual(evidence["schema"], RPMLINT_EVIDENCE_SCHEMA)
        self.assertEqual(evidence["rpm_identity"], identity)
        self.assertEqual(evidence["rpm_payload_digest"], payload)
        self.assertEqual(evidence["spec_sha256"], digest(self.spec.read_bytes()))
        self.assertEqual(evidence["package_sha256"], digest(self.rpm.read_bytes()))
        self.assertTrue(evidence["clean"])
        self.assertEqual(evidence["status"], "pass")
        self.assertEqual(len(receipts), 1)

    def test_four_products_synthetic_fixtures(self):
        products = [
            ("theme-forge-stellar-loom", "noarch", "0.4.0"),
            ("theme-forge-solar-sail", "noarch", "0.4.0"),
            ("theme-forge-stellar-burst", "x86_64", "0.6.1"),
            ("theme-forge-nebular-fusion", "x86_64", "0.6.1"),
        ]

        def handler(argv, cwd=None, env=None):
            if "--version" in argv:
                return CommandReceipt(argv, 0, b"rpmlint version 2.5.0\n", b"")
            return CommandReceipt(
                argv,
                0,
                b"1 packages and 1 specfiles checked; 0 errors, 0 warnings, 0 filtered.\n",
                b"",
            )

        runner = MockCommandRunner(
            available_tools={"rpmlint": "/usr/bin/rpmlint"},
            handlers={"rpmlint": handler},
        )

        for name, arch, ver in products:
            with self.subTest(product=name, arch=arch):
                spec_p = self.root / f"{name}.spec"
                spec_p.write_bytes(f"Name: {name}\nVersion: {ver}\n".encode())
                rpm_p = self.root / f"{name}-{ver}-1.fc43.{arch}.rpm"
                rpm_p.write_bytes(f"rpm-content-{name}".encode())

                ident = {"name": name, "version": ver, "release": "1.fc43", "arch": arch}
                payload = {"tag": "PAYLOADSHA256", "algo_tag": "PAYLOADSHA256ALGO",
                           "payload_digest": digest(b"payload"), "payload_digest_algo": "sha256"}

                ev, receipts = execute_rpmlint(
                    runner, spec_p, rpm_p, name,
                    rpm_identity=ident, rpm_payload_digest=payload,
                )
                self.assertEqual(ev["product"], name)
                self.assertEqual(ev["rpm_identity"]["arch"], arch)
class RpmLintIntegratedExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.spec = self.root / "pkg.spec"
        self.spec.write_bytes(b"Name: pkg\nVersion: 1.0.0\n")
        self.rpm = self.root / "pkg-1.0.0-1.fc43.x86_64.rpm"
        self.rpm.write_bytes(b"real-rpm-bytes-for-test")

    def test_tool_identities_use_complete_strict_framed_receipts(self):
        from rs9.rpm_lint_policy import _raw_blockers
        identity_bound = 1024
        valid = (b'2.8.0\n', b'rpmlint|2.8.0|2.fc43|noarch\n')
        malformed = (b'', b'\xff\n', b'x' * identity_bound, b'x' * (identity_bound + 1))
        for probe in (0, 1):
            framing_errors = (valid[probe][:-1], valid[probe][:-1] + b' \n',
                              valid[probe] + b'\n', valid[probe] + b'trailing\n',
                              valid[probe] + b'x' * 65536 + b'\xff\n')
            if probe == 1:
                framing_errors += (b'rpmlint|' + b'ghp_' + b'a' * 36 + b'|2.fc43|noarch\n',)
            for raw, stderr in [(valid[probe], b''), *[(b, b'') for b in (*malformed, *framing_errors)],
                                (valid[probe], b'probe diagnostic\n')]:
                with self.subTest(probe=probe, size=len(raw), stderr=bool(stderr)):
                    observed = []
                    def handler(argv, **kwargs):
                        which = 0 if '--version' in argv else 1 if '-q' in argv else None
                        out = (raw if which == probe else valid[which]) if which is not None else (
                            b'pkg.noarch: E: env-script-interpreter /usr/lib/pkg/run.js /usr/bin/env node\n'
                            b'1 packages and 1 specfiles checked; 1 errors, 0 warnings, 0 filtered.\n')
                        receipt = CommandReceipt(argv, 0 if which is not None else 64,
                                                 out, stderr if which == probe else b'', executed=True)
                        observed.append(receipt)
                        return receipt
                    runner = MockCommandRunner(available_tools={'rpm':'/usr/bin/rpm', 'rpmlint':'/usr/bin/rpmlint'},
                        handlers={'rpm':handler, 'rpmlint':handler})
                    evidence, receipts = execute_rpmlint(runner, self.spec, self.rpm, 'pkg',
                                                        cwd=self.root, allow_policy=True)
                    identity = evidence['tool_version'] if probe == 0 else evidence['tool_version']['package_query']
                    receipt = observed[probe + 1]
                    self.assertEqual(identity['stdout_sha256'], digest(raw))
                    self.assertEqual(identity['stderr_sha256'], digest(stderr))
                    self.assertEqual(identity['stdout_length'], len(raw))
                    self.assertEqual(identity['stderr_length'], len(stderr))
                    self.assertEqual(identity['exit_code'], 0)
                    self.assertLessEqual(len(receipt.stdout_text.encode('utf-8')), 65536)
                    self.assertIs(receipts[0], observed[0])
                    self.assertEqual(evidence['tool_receipt']['exit_code'], 64)
                    policy = {'tool_constraints': {'filtered_count': 0}}
                    valid_input = raw == valid[probe] and not stderr
                    self.assertEqual(_raw_blockers(evidence, policy), [] if valid_input else ['tool-identity-mismatch'])
                    self.assertEqual(identity['version'], valid[probe][:-1].decode() if valid_input else 'query-invalid')
                    if not valid_input:
                        self.assertIn('reason_token', identity)
                        if len(raw) == identity_bound:
                            self.assertEqual(identity['reason_token'], 'incomplete-framing')
                        if len(raw) > identity_bound:
                            self.assertEqual(identity['reason_token'], 'stream-limit-exceeded')
                        # A malformed diagnostic probe never replaces raw lint status or counts.
                        self.assertEqual(len(evidence['error_records']), evidence['findings_summary']['errors'])

    def test_version_probe_variations(self):
        # 1. Version succeeds
        calls = []
        def handler_succeeds(argv, **kw):
            calls.append(list(argv))
            if "--version" in argv:
                return CommandReceipt(argv, 0, b"rpmlint 2.6.0\n", b"", executed=True)
            if "-q" in argv:
                return CommandReceipt(argv, 0, b"rpmlint|2.6.0|1.fc43|x86_64\n", b"", executed=True)
            return CommandReceipt(argv, 0, b"1 packages and 1 specfiles checked; 0 errors, 0 warnings.\n", b"", executed=True)

        runner = MockCommandRunner(available_tools={"rpmlint": "/usr/bin/rpmlint", "rpm": "/usr/bin/rpm"},
                                   handlers={"rpmlint": handler_succeeds, "rpm": handler_succeeds})
        ev, receipts = execute_rpmlint(runner, self.spec, self.rpm, "pkg", cwd=self.root)
        self.assertTrue(ev["clean"])
        self.assertEqual(ev["tool_version"]["version"], "rpmlint 2.6.0")
        self.assertEqual(ev["tool_version"]["exit_code"], 0)
        self.assertEqual(calls[0], ["rpmlint", str(self.spec), str(self.rpm)])
        self.assertEqual(receipts[0].command, ["rpmlint", str(self.spec), str(self.rpm)])
        self.assertFalse(hasattr(receipts[0], "argv"))

        # 2. Version fails with non-zero exit code
        calls.clear()
        def handler_fails(argv, **kw):
            calls.append(list(argv))
            if "--version" in argv:
                return CommandReceipt(argv, 127, b"", b"rpmlint: not found\n", executed=True)
            return CommandReceipt(argv, 1,
                b"pkg.x86_64: E: explicit-lib-dependency nodejs\n1 packages and 1 specfiles checked; 1 errors, 0 warnings.\n",
                b"", executed=True)

        runner_fail = MockCommandRunner(available_tools={"rpmlint": "/usr/bin/rpmlint"},
                                        handlers={"rpmlint": handler_fails})
        with self.assertRaises(ContractError) as caught:
            execute_rpmlint(runner_fail, self.spec, self.rpm, "pkg", cwd=self.root)
        err = caught.exception
        self.assertEqual(err.code, "RPMLINT_FAILED")
        self.assertEqual(err.details["diagnostic_token"], "explicit-lib-dependency")
        self.assertEqual(err.evidence["tool_version"]["version"], "query-failed")
        self.assertEqual(err.evidence["tool_version"]["exit_code"], 127)

        # 3. Version throws exception
        calls.clear()
        def handler_throws(argv, **kw):
            calls.append(list(argv))
            if "--version" in argv:
                raise ContractError("TOOL_CRASH", "version probe crashed")
            if "-q" in argv:
                raise OSError("rpmdb corrupted")
            return CommandReceipt(argv, 1,
                b"pkg.x86_64: E: binary-or-shlib-defines-rpath /opt\n1 packages and 1 specfiles checked; 1 errors, 0 warnings.\n",
                b"", executed=True)

        runner_throw = MockCommandRunner(available_tools={"rpmlint": "/usr/bin/rpmlint", "rpm": "/usr/bin/rpm"},
                                         handlers={"rpmlint": handler_throws, "rpm": handler_throws})
        with self.assertRaises(ContractError) as caught:
            execute_rpmlint(runner_throw, self.spec, self.rpm, "pkg", cwd=self.root)
        err = caught.exception
        self.assertEqual(err.code, "RPMLINT_FAILED")
        self.assertEqual(err.details["diagnostic_token"], "binary-or-shlib-defines-rpath")
        self.assertEqual(err.evidence["tool_version"]["version"], "query-unavailable")
        self.assertEqual(err.evidence["tool_version"]["package_query"]["status"], "unavailable")
        # Causal rpmlint command was run first
        self.assertEqual(calls[0], ["rpmlint", str(self.spec), str(self.rpm)])

    def test_zero_nonzero_cleanliness_combinations(self):
        cases = [
            # (exit_code, output_bytes, expected_clean, expected_reason)
            (0, b"1 packages and 1 specfiles checked; 0 errors, 0 warnings.\n", True, "clean"),
            (0, b"pkg.x86_64: E: test-err detail\n1 packages and 1 specfiles checked; 1 errors, 0 warnings.\n", False, "lint-errors"),
            (64, b"1 packages and 1 specfiles checked; 0 errors, 0 warnings.\n", False, "lint-exit64"),
            (1, b"1 packages and 1 specfiles checked; 0 errors, 0 warnings.\n", False, "exit-nonzero"),
            (1, b"pkg.x86_64: E: test-err detail\n1 packages and 1 specfiles checked; 1 errors, 0 warnings.\n", False, "lint-errors"),
            (0, b"unexpected garbage line without summary\n", False, "malformed-output"),
            (0, b"pkg.x86_64: E: err1 msg\n1 packages and 1 specfiles checked; 2 errors, 0 warnings.\n", False, "count-mismatch"),
            (0, b"2 packages and 1 specfiles checked; 0 errors, 0 warnings.\n", False, "input-count-mismatch"),
        ]

        for exit_code, out_bytes, expected_clean, expected_reason in cases:
            with self.subTest(exit_code=exit_code, expected_reason=expected_reason):
                receipt = CommandReceipt(["rpmlint", str(self.spec), str(self.rpm)], exit_code, out_bytes, b"", executed=True)
                runner = MockCommandRunner(
                    available_tools={"rpmlint": "/usr/bin/rpmlint"},
                    handlers={"rpmlint": lambda argv, **kw: receipt},
                )
                if expected_clean:
                    ev, r = execute_rpmlint(runner, self.spec, self.rpm, "pkg", cwd=self.root)
                    self.assertTrue(ev["clean"])
                    self.assertEqual(ev["reason_token"], expected_reason)
                else:
                    with self.assertRaises(ContractError) as caught:
                        execute_rpmlint(runner, self.spec, self.rpm, "pkg", cwd=self.root)
                    err = caught.exception
                    self.assertEqual(err.code, "RPMLINT_FAILED")
                    self.assertEqual(err.details["reason_token"], expected_reason)
                    self.assertFalse(err.evidence["clean"])

    def test_missing_package_and_spec_handling(self):
        missing_spec = self.root / "nonexistent.spec"
        missing_rpm = self.root / "nonexistent.rpm"

        runner = MockCommandRunner(
            available_tools={"rpmlint": "/usr/bin/rpmlint"},
            handlers={"rpmlint": lambda argv, **kw: CommandReceipt(
                argv, 1,
                b"error: spec file not found\n1 packages and 1 specfiles checked; 1 errors, 0 warnings.\n",
                b"file missing\n", executed=True)},
        )

        # 1. Missing spec file
        with self.assertRaises(ContractError) as caught:
            execute_rpmlint(runner, missing_spec, self.rpm, "pkg", cwd=self.root)
        err = caught.exception
        self.assertEqual(err.code, "RPMLINT_FAILED")
        self.assertEqual(err.spec_sha256, "")
        self.assertEqual(err.package_sha256, digest(self.rpm.read_bytes()))
        self.assertEqual(err.spec_path, str(missing_spec))

        # 2. Missing rpm file
        with self.assertRaises(ContractError) as caught:
            execute_rpmlint(runner, self.spec, missing_rpm, "pkg", cwd=self.root)
        err = caught.exception
        self.assertEqual(err.code, "RPMLINT_FAILED")
        self.assertEqual(err.package_sha256, "")
        self.assertEqual(err.spec_sha256, digest(self.spec.read_bytes()))
        self.assertEqual(err.package_path, str(missing_rpm))

        # 3. Missing both
        with self.assertRaises(ContractError) as caught:
            execute_rpmlint(runner, missing_spec, missing_rpm, "pkg", cwd=self.root)
        err = caught.exception
        self.assertEqual(err.code, "RPMLINT_FAILED")
        self.assertEqual(err.spec_sha256, "")
        self.assertEqual(err.package_sha256, "")

    def test_diagnostic_filesystem_failure_does_not_replace_original_lint_error(self):
        runner = MockCommandRunner(
            available_tools={"rpmlint": "/usr/bin/rpmlint"},
            handlers={"rpmlint": lambda argv, **kw: CommandReceipt(
                argv, 1,
                b"pkg.x86_64: E: explicit-lib-dependency nodejs\n1 packages and 1 specfiles checked; 1 errors, 0 warnings.\n",
                b"", executed=True)},
        )

        with patch("pathlib.Path.write_bytes", side_effect=OSError("Read-only file system")):
            # write_bytes for rpmlint-findings.json will raise OSError, but execute_rpmlint
            # must catch it and preserve the original RPMLINT_FAILED error!
            with self.assertRaises(ContractError) as caught:
                execute_rpmlint(runner, self.spec, self.rpm, "pkg", cwd=self.root)

        err = caught.exception
        self.assertEqual(err.code, "RPMLINT_FAILED")
        self.assertEqual(err.details["diagnostic_token"], "explicit-lib-dependency")
        self.assertEqual(err.details["reason_token"], "lint-errors")
        self.assertIsNotNone(err.receipt)
        self.assertEqual(err.receipt.command, ["rpmlint", str(self.spec), str(self.rpm)])
        self.assertFalse(hasattr(err.receipt, "argv"))

    def test_collection_failure_does_not_fabricate_counts(self):
        receipt = CommandReceipt(["rpmlint",str(self.spec),str(self.rpm)],64,b"unavailable-stream",b"",executed=True)
        runner = MockCommandRunner(available_tools={"rpmlint":"rpmlint"},
                                  handlers={"rpmlint":lambda command,**kw:receipt})
        with patch("rs9.rpm_lint.build_rpmlint_evidence",side_effect=ContractError("DIAGNOSTIC_LIMIT","fixture-limit")):
            with self.assertRaises(ContractError) as caught:
                execute_rpmlint(runner,self.spec,self.rpm,"pkg",cwd=self.root)
        error=caught.exception
        self.assertEqual(error.code,"RPMLINT_FAILED")
        self.assertIs(error.receipt,receipt)
        self.assertIsNone(error.evidence["findings_summary"])
        self.assertFalse(error.evidence["parse_complete"])
        self.assertEqual(error.evidence["evidence_status"],"collection-failed")
        self.assertEqual(error.evidence["tool_receipt"]["stdout_sha256"],receipt.stdout_sha256)

    def test_complete_error_records_parsing(self):
        output = (
            "pkg.x86_64: E: non-executable-script /usr/lib/theme-forge-stellar-burst/dist/cli.js 644 /usr/bin/env node\n"
            "pkg.x86_64: E: env-script-interpreter /usr/lib/theme-forge-stellar-loom/bin/tfsl.js /usr/bin/env node\n"
            "pkg.x86_64: E: files-duplicated-waste 214129\n"
            "pkg.x86_64: E: explicit-lib-dependency dbus-libs\n"
            "pkg.x86_64: E: no-changelogname-tag\n"
            "1 packages and 0 specfiles checked; 5 errors, 0 warnings, 0 filtered.\n"
        )
        parsed = parse_rpmlint_output(output, exit_code=64)
        self.assertTrue(parsed["parse_complete"])
        records = parsed["error_records"]
        self.assertEqual(len(records), 5)

        # non-executable-script
        rec0 = records[0]
        self.assertEqual(rec0["code"], "non-executable-script")
        self.assertEqual(rec0["path"], "/usr/lib/theme-forge-stellar-burst/dist/cli.js")
        self.assertEqual(rec0["mode"], "644")
        self.assertEqual(rec0["interpreter"], "/usr/bin/env node")

        # env-script-interpreter
        rec1 = records[1]
        self.assertEqual(rec1["code"], "env-script-interpreter")
        self.assertEqual(rec1["path"], "/usr/lib/theme-forge-stellar-loom/bin/tfsl.js")
        self.assertEqual(rec1["interpreter"], "/usr/bin/env node")

        # files-duplicated-waste
        rec2 = records[2]
        self.assertEqual(rec2["code"], "files-duplicated-waste")
        self.assertEqual(rec2["waste_bytes"], 214129)

        # explicit-lib-dependency
        rec3 = records[3]
        self.assertEqual(rec3["code"], "explicit-lib-dependency")
        self.assertEqual(rec3["dependency"], "dbus-libs")

        # no-changelogname-tag
        rec4 = records[4]
        self.assertEqual(rec4["code"], "no-changelogname-tag")

    def test_warnings_dropped_first_when_bounding_findings(self):
        lines = []
        for i in range(15):
            lines.append(f"pkg.x86_64: E: non-executable-script /usr/lib/theme-forge-stellar-burst/file{i}.js 644 /usr/bin/env node")
        for i in range(139):
            lines.append(f"pkg.x86_64: W: files-duplicate warning-detail-{i}")
        lines.append("1 packages and 0 specfiles checked; 15 errors, 139 warnings, 0 filtered.\n")

        parsed = parse_rpmlint_output("\n".join(lines), exit_code=64)
        self.assertTrue(parsed["parse_complete"])
        self.assertTrue(parsed["findings_truncated"])
        self.assertEqual(len(parsed["findings"]), 100)

        # All 15 errors MUST be in findings (warnings were dropped first!)
        error_findings = [f for f in parsed["findings"] if f["level"] == "E"]
        self.assertEqual(len(error_findings), 15)
        # Remaining 85 slots filled with warnings
        warning_findings = [f for f in parsed["findings"] if f["level"] == "W"]
        self.assertEqual(len(warning_findings), 85)

        # Complete error_records retains all 15 records
        self.assertEqual(len(parsed["error_records"]), 15)
        self.assertFalse(parsed["error_overflow"])

    def test_error_overflow_fails_closed(self):
        lines = [f"pkg.x86_64: E: err-{i} msg" for i in range(513)]
        lines.append("1 packages and 0 specfiles checked; 513 errors, 0 warnings, 0 filtered.\n")

        parsed = parse_rpmlint_output("\n".join(lines), exit_code=64, strict=False)
        self.assertFalse(parsed["parse_complete"])
        self.assertTrue(parsed["error_overflow"])
        self.assertEqual(parsed["reason_token"], "error-overflow")

        with self.assertRaises(ContractError) as caught:
            parse_rpmlint_output("\n".join(lines), exit_code=64, strict=True)
        self.assertEqual(caught.exception.details.get("reason_token"), "error-overflow")

    def test_allow_policy_flag_on_execute_rpmlint(self):
        error_output = (
            b"pkg.x86_64: E: non-executable-script /usr/lib/theme-forge-stellar-burst/dist/cli.js 644 /usr/bin/env node\n"
            b"1 packages and 1 specfiles checked; 1 errors, 0 warnings, 0 filtered.\n"
        )
        receipt_exit64 = CommandReceipt(
            ["rpmlint", str(self.spec), str(self.rpm)], 64, error_output, b"", executed=True
        )
        runner_exit64 = MockCommandRunner(
            available_tools={"rpmlint": "/usr/bin/rpmlint"},
            handlers={"rpmlint": lambda argv, **kw: receipt_exit64},
        )

        # 1. Old default allow_policy=False remains raising ContractError
        with self.assertRaises(ContractError) as caught:
            execute_rpmlint(runner_exit64, self.spec, self.rpm, "pkg", cwd=self.root, allow_policy=False)
        self.assertEqual(caught.exception.code, "RPMLINT_FAILED")

        # 2. allow_policy=True returns raw lint failures when complete recognized result
        ev, receipts = execute_rpmlint(runner_exit64, self.spec, self.rpm, "pkg", cwd=self.root, allow_policy=True)
        self.assertFalse(ev["clean"])
        self.assertEqual(ev["status"], "fail")
        self.assertEqual(ev["reason_token"], "lint-errors")
        self.assertEqual(receipts[0].exit_code, 64)
        self.assertEqual(ev["tool_receipt"]["command"], ["rpmlint", self.spec.name, self.rpm.name])
        self.assertEqual(len(ev["error_records"]), 1)
        self.assertEqual(ev["error_records"][0]["code"], "non-executable-script")

        # 3. allow_policy=True STILL fails closed on tool execution error (exit 1)
        receipt_exit1 = CommandReceipt(
            ["rpmlint", str(self.spec), str(self.rpm)], 1, error_output, b"rpmlint crashed\n", executed=True
        )
        runner_exit1 = MockCommandRunner(
            available_tools={"rpmlint": "/usr/bin/rpmlint"},
            handlers={"rpmlint": lambda argv, **kw: receipt_exit1},
        )
        with self.assertRaises(ContractError) as caught:
            execute_rpmlint(runner_exit1, self.spec, self.rpm, "pkg", cwd=self.root, allow_policy=True)
        self.assertEqual(caught.exception.code, "RPMLINT_FAILED")

        # 4. allow_policy=True STILL fails closed on malformed output
        receipt_malformed = CommandReceipt(
            ["rpmlint", str(self.spec), str(self.rpm)], 64, b"malformed line without summary\n", b"", executed=True
        )
        runner_malformed = MockCommandRunner(
            available_tools={"rpmlint": "/usr/bin/rpmlint"},
            handlers={"rpmlint": lambda argv, **kw: receipt_malformed},
        )
        with self.assertRaises(ContractError) as caught:
            execute_rpmlint(runner_malformed, self.spec, self.rpm, "pkg", cwd=self.root, allow_policy=True)
        self.assertEqual(caught.exception.code, "RPMLINT_FAILED")

    def test_large_stream_beyond_64k_with_900_warnings_and_15_errors(self):
        # 1. Construct >64KiB stream with 900 warnings, 15 errors beyond preview, and summary at end
        warning_lines = []
        for i in range(900):
            warning_lines.append(f"theme-forge-stellar-burst.x86_64: W: warning-check-{i % 25} sample warning detail message number {i:04d}\n")

        header = "==== rpmlint session starts ====\nrpmlint: 2.8.0\nchecks: 40, packages: 1\n"

        error_lines = []
        for i in range(15):
            error_lines.append(
                f"theme-forge-stellar-burst.x86_64: E: non-executable-script /usr/lib/theme-forge-stellar-burst/dist/worker{i}.js 644 /usr/bin/env node\n"
            )

        summary_line = "1 packages and 1 specfiles checked; 15 errors, 900 warnings, 0 filtered.\n"

        stdout_text = header + "".join(warning_lines) + "".join(error_lines) + summary_line
        stdout_bytes = stdout_text.encode("utf-8")

        # Verify stream is >64KiB
        self.assertGreater(len(stdout_bytes), 64 * 1024)

        # Real CommandReceipt caps stdout_text preview at 64KiB (65536 bytes)
        receipt = CommandReceipt(
            ["rpmlint", str(self.spec), str(self.rpm)],
            64,
            stdout_bytes,
            b"",
            executed=True,
        )
        self.assertLessEqual(len(receipt.stdout_text), 65536)
        # Verify preview does NOT contain the errors or summary (they are beyond 64KiB!)
        self.assertNotIn("worker14.js", receipt.stdout_text)
        self.assertNotIn("1 packages and 1 specfiles checked", receipt.stdout_text)
        self.assertEqual(receipt.stdout_sha256, digest(stdout_bytes))

        runner = MockCommandRunner(
            available_tools={"rpmlint": "/usr/bin/rpmlint"},
            handlers={"rpmlint": lambda argv, **kw: receipt},
        )

        # execute_rpmlint with allow_policy=True
        ev, receipts = execute_rpmlint(
            runner,
            self.spec,
            self.rpm,
            "theme-forge-stellar-burst",
            cwd=self.root,
            allow_policy=True,
        )

        # Raw status never policy rewritten!
        self.assertFalse(ev["clean"])
        self.assertEqual(ev["status"], "fail")
        self.assertEqual(ev["reason_token"], "lint-errors")

        # Raw hash integrity
        self.assertEqual(receipts[0].stdout_sha256, receipt.stdout_sha256)
        self.assertEqual(ev["tool_receipt"]["stdout_sha256"], receipt.stdout_sha256)
        self.assertEqual(ev["tool_receipt"]["stdout_bytes"], len(stdout_bytes))
        self.assertEqual(ev["tool_receipt"]["exit_code"], 64)

        # Exact counts preserved
        self.assertEqual(ev["counts"]["E"], 15)
        self.assertEqual(ev["counts"]["W"], 900)
        self.assertEqual(ev["findings_summary"]["errors"], 15)
        self.assertEqual(ev["findings_summary"]["warnings"], 900)
        self.assertTrue(ev["parse_complete"])
        self.assertEqual(ev["unparsed_count"], 0)

        # Complete errors preserved before sample caps
        self.assertEqual(len(ev["error_records"]), 15)
        self.assertFalse(ev["error_overflow"])
        for idx, rec in enumerate(ev["error_records"]):
            self.assertEqual(rec["code"], "non-executable-script")
            self.assertEqual(rec["path"], f"/usr/lib/theme-forge-stellar-burst/dist/worker{idx}.js")
            self.assertEqual(rec["mode"], "644")
            self.assertEqual(rec["interpreter"], "/usr/bin/env node")
            self.assertTrue(rec["arguments_complete"])

        # Warning sample bounds:
        # findings bounded by MAX_FINDINGS (100)
        self.assertEqual(len(ev["findings"]), MAX_FINDINGS)
        self.assertTrue(ev["findings_truncated"])
        # All 15 errors MUST be prioritized in findings
        error_findings = [f for f in ev["findings"] if f["level"] == "E"]
        self.assertEqual(len(error_findings), 15)
        warning_findings = [f for f in ev["findings"] if f["level"] == "W"]
        self.assertEqual(len(warning_findings), 85)
        # Group samples bounded at 3
        for g in ev["groups"]:
            self.assertLessEqual(len(g["samples"]), 3)

    def test_exact_max_stream_bytes_and_overflow_by_one(self):
        # 1. Test exact MAX_STREAM_BYTES
        header = "==== rpmlint session starts ====\nrpmlint: 2.8.0\n"
        summary = "1 packages and 1 specfiles checked; 0 errors, 1 warnings, 0 filtered.\n"
        prefix = "pkg.noarch: W: warning-check "
        target_len = MAX_STREAM_BYTES - len(header.encode("utf-8")) - len(summary.encode("utf-8")) - len(prefix.encode("utf-8")) - 1
        self.assertGreater(target_len, 0)
        warning_line = prefix + ("a" * target_len) + "\n"
        exact_text = header + warning_line + summary
        exact_bytes = exact_text.encode("utf-8")
        self.assertEqual(len(exact_bytes), MAX_STREAM_BYTES)

        # Parser accepts exact MAX_STREAM_BYTES
        parsed = parse_rpmlint_output(exact_text, exit_code=0, strict=True)
        self.assertTrue(parsed["parse_complete"])
        self.assertEqual(parsed["counts"]["W"], 1)
        self.assertFalse(parsed["findings_truncated"])

        # build_rpmlint_evidence accepts exact MAX_STREAM_BYTES
        receipt_exact = CommandReceipt(["rpmlint"], 0, exact_bytes, b"", executed=True)
        ev_exact = build_rpmlint_evidence(receipt_exact, self.spec, self.rpm, "pkg")
        self.assertTrue(ev_exact["clean"])
        self.assertEqual(ev_exact["status"], "pass")
        self.assertEqual(ev_exact["tool_receipt"]["stdout_bytes"], MAX_STREAM_BYTES)
        self.assertEqual(ev_exact["tool_receipt"]["stdout_sha256"], digest(exact_bytes))

        # 2. Test MAX_STREAM_BYTES + 1
        overflow_text = header + prefix + ("a" * (target_len + 1)) + "\n" + summary
        overflow_bytes = overflow_text.encode("utf-8")
        self.assertEqual(len(overflow_bytes), MAX_STREAM_BYTES + 1)

        # Parser fails on MAX_STREAM_BYTES + 1
        with self.assertRaises(ContractError) as caught:
            parse_rpmlint_output(overflow_text, exit_code=0, strict=True)
        self.assertEqual(caught.exception.details.get("reason_token"), "malformed-output")

        # Reader / build_rpmlint_evidence produces failing evidence on overflow
        receipt_overflow = CommandReceipt(["rpmlint"], 0, overflow_bytes, b"", executed=True)
        ev_overflow = build_rpmlint_evidence(receipt_overflow, self.spec, self.rpm, "pkg")
        self.assertFalse(ev_overflow["clean"])
        self.assertEqual(ev_overflow["status"], "fail")
        self.assertFalse(ev_overflow["parse_complete"])
        self.assertEqual(ev_overflow["reason_token"], "stream-limit-exceeded")
        self.assertEqual(ev_overflow["tool_receipt"]["stdout_bytes"], MAX_STREAM_BYTES + 1)
        self.assertEqual(ev_overflow["tool_receipt"]["stdout_sha256"], digest(overflow_bytes))

    def test_invalid_utf8_and_incomplete_record_past_64k(self):
        # 1. Invalid UTF8 past 64KiB
        lines = [f"pkg.noarch: W: warn-{i % 30:04d} message number {i:04d}\n" for i in range(2000)]
        valid_prefix = "".join(lines)
        valid_bytes = valid_prefix.encode("utf-8")
        self.assertGreater(len(valid_bytes), 64 * 1024)

        # Append corrupt non-UTF8 sequence past 64KiB
        bad_utf8_bytes = valid_bytes[:70000] + b"\xff\xfe\x80" + b"\n1 packages and 1 specfiles checked; 0 errors, 1 warnings.\n"
        receipt_bad = CommandReceipt(["rpmlint"], 0, bad_utf8_bytes, b"", executed=True)

        ev_bad = build_rpmlint_evidence(receipt_bad, self.spec, self.rpm, "pkg")
        self.assertFalse(ev_bad["clean"])
        self.assertEqual(ev_bad["status"], "fail")
        self.assertFalse(ev_bad["parse_complete"])
        self.assertEqual(ev_bad["reason_token"], "stream-decode-failed")
        self.assertEqual(ev_bad["tool_receipt"]["stdout_bytes"], len(bad_utf8_bytes))
        self.assertEqual(ev_bad["tool_receipt"]["stdout_sha256"], digest(bad_utf8_bytes))
        self.assertIsNone(ev_bad["findings_summary"])

        # Reader error has no policy recognition in execute_rpmlint
        runner = MockCommandRunner(
            available_tools={"rpmlint": "/usr/bin/rpmlint"},
            handlers={"rpmlint": lambda argv, **kw: receipt_bad},
        )
        with self.assertRaises(ContractError) as caught:
            execute_rpmlint(runner, self.spec, self.rpm, "pkg", cwd=self.root, allow_policy=True)
        self.assertEqual(caught.exception.code, "RPMLINT_FAILED")
        self.assertEqual(caught.exception.details.get("reason_token"), "stream-decode-failed")

        # 2. Incomplete error record past 64KiB
        incomp_error = "pkg.x86_64: E: non-executable-script\n"
        incomp_text = valid_prefix[:70000] + "\n" + incomp_error + "1 packages and 1 specfiles checked; 1 errors, 0 warnings.\n"
        receipt_incomp = CommandReceipt(["rpmlint"], 64, incomp_text.encode("utf-8"), b"", executed=True)
        ev_incomp = build_rpmlint_evidence(receipt_incomp, self.spec, self.rpm, "pkg")
        self.assertFalse(ev_incomp["clean"])
        self.assertEqual(ev_incomp["status"], "fail")
        self.assertFalse(ev_incomp["parse_complete"])
        self.assertTrue(ev_incomp["error_overflow"])
        self.assertEqual(ev_incomp["reason_token"], "error-overflow")

        # 3. Missing newline framing past 64KiB
        warn_count = 1500
        warn_lines = [f"pkg.noarch: W: warn-{i % 30:04d} message number {i:04d}\n" for i in range(warn_count)]
        body = "".join(warn_lines)
        summary = f"1 packages and 1 specfiles checked; 0 errors, {warn_count} warnings."
        unframed_bytes = (body + summary).encode("utf-8")
        self.assertGreater(len(unframed_bytes), 64 * 1024)
        receipt_unframed = CommandReceipt(["rpmlint"], 0, unframed_bytes, b"", executed=True)
        ev_unframed = build_rpmlint_evidence(receipt_unframed, self.spec, self.rpm, "pkg")
        self.assertFalse(ev_unframed["clean"])
        self.assertEqual(ev_unframed["status"], "fail")
        self.assertFalse(ev_unframed["parse_complete"])
        self.assertEqual(ev_unframed["reason_token"], "malformed-output")

        # 4. Trailing corruption past summary fails
        corrupt_trailing = body + summary + "\ncorrupt-trailing-line\n"
        with self.assertRaises(ContractError) as caught:
            parse_rpmlint_output(corrupt_trailing, exit_code=0, strict=True)
        self.assertEqual(caught.exception.details.get("reason_token"), "malformed-output")

    def test_full_configuration_digest_beyond_64k(self):
        # Generate configuration paths extending beyond 64KiB
        config_lines = [f"    /etc/rpmlint/generated-rule-{i:04d}.toml\n" for i in range(2000)]
        header = "==== rpmlint session starts ====\nrpmlint: 2.8.0\nconfiguration:\n"
        summary = "1 packages and 1 specfiles checked; 0 errors, 0 warnings.\n"
        full_text = header + "".join(config_lines) + summary
        full_bytes = full_text.encode("utf-8")
        self.assertGreater(len(full_bytes), 64 * 1024)

        receipt = CommandReceipt(["rpmlint"], 0, full_bytes, b"", executed=True)
        # Verify receipt.stdout_text was capped at 64KiB
        self.assertLessEqual(len(receipt.stdout_text), 65536)

        ev = build_rpmlint_evidence(receipt, self.spec, self.rpm, "pkg")
        self.assertTrue(ev["clean"])
        self.assertEqual(ev["status"], "pass")

        # Full configuration listing digest reflects all 2000 paths
        expected_paths = [f"/etc/rpmlint/generated-rule-{i:04d}.toml" for i in range(2000)]
        expected_digest = digest(canonical(expected_paths))
        self.assertEqual(ev["effective_configuration"]["listing_sha256"], expected_digest)

        # Partial receipt.stdout_text would have missed trailing paths
        partial_paths = [line.strip() for line in receipt.stdout_text.splitlines() if line.startswith((" ", "\t")) and line.strip().startswith("/")]
        self.assertNotEqual(expected_digest, digest(canonical(partial_paths)))

    def test_custody_diagnostic_bytes_large_parsed_evidence_and_blocked_policy(self):
        from rs9.hosted_custody import diagnostic_bytes
        from rs9.rpm_lint_policy import evaluate_policy
        import uuid

        # Generate large stream >64KiB with 900 warnings and 15 errors
        warning_lines = [f"theme-forge-stellar-burst.x86_64: W: warn-{i % 25:03d} detail warning message {i:04d}\n" for i in range(900)]
        header = "==== rpmlint session starts ====\nrpmlint: 2.8.0\nconfiguration:\n    /etc/rpmlint/fedora.toml\n"
        error_lines = [
            f"theme-forge-stellar-burst.x86_64: E: non-executable-script /usr/lib/theme-forge-stellar-burst/dist/worker{i}.js 644 /usr/bin/env node\n"
            for i in range(15)
        ]
        summary_line = "1 packages and 1 specfiles checked; 15 errors, 900 warnings, 0 filtered.\n"
        stdout_bytes = (header + "".join(warning_lines) + "".join(error_lines) + summary_line).encode("utf-8")
        self.assertGreater(len(stdout_bytes), 64 * 1024)

        receipt = CommandReceipt(
            ["rpmlint", str(self.spec), str(self.rpm)],
            64,
            stdout_bytes,
            b"",
            executed=True,
        )

        runner = MockCommandRunner(
            available_tools={"rpmlint": "/usr/bin/rpmlint", "rpm": "/usr/bin/rpm"},
            handlers={
                "rpmlint": lambda argv, **kw: CommandReceipt(argv, 0, b"rpmlint 2.8.0\n", b"", executed=True) if "--version" in argv else receipt,
                "rpm": lambda argv, **kw: CommandReceipt(argv, 0, b"rpmlint|2.8.0|2.fc43|noarch\n", b"", executed=True),
            },
        )

        ev, receipts = execute_rpmlint(
            runner,
            self.spec,
            self.rpm,
            "theme-forge-stellar-burst",
            cwd=self.root,
            allow_policy=True,
        )

        # Raw lint status remains "fail" (never altered to pass)
        self.assertFalse(ev["clean"])
        self.assertEqual(ev["status"], "fail")
        self.assertEqual(len(ev["error_records"]), 15)

        # Diagnostic JSON written to /private/tmp
        run_id = uuid.uuid4().hex[:8]
        tmp_dir = Path("/private/tmp")
        diag_path = tmp_dir / f"test-rpmlint-diag-{run_id}.json"
        pretty_path = tmp_dir / f"test-rpmlint-pretty-{run_id}.json"
        policy_path = tmp_dir / f"test-policy-diag-{run_id}.json"

        try:
            # 1. canonical serialization passes diagnostic_bytes
            diag_path.write_bytes(canonical(ev))
            self.assertLessEqual(diag_path.stat().st_size, 64 * 1024)
            data_canonical = diagnostic_bytes(diag_path)
            self.assertEqual(data_canonical, canonical(ev))

            # 2. pretty JSON (indent=2) passes diagnostic_bytes
            pretty_bytes = (json.dumps(ev, indent=2) + "\n").encode("utf-8")
            pretty_path.write_bytes(pretty_bytes)
            self.assertLessEqual(pretty_path.stat().st_size, 64 * 1024)
            data_pretty = diagnostic_bytes(pretty_path)
            self.assertEqual(data_pretty, pretty_bytes)

            # 3. Blocked policy evaluation passes diagnostic_bytes
            inputs = {
                "project_id": "theme-forge-stellar-burst",
                "version": "0.6.1",
                "arch": "x86_64",
                "system": "x86_64-linux",
            }
            policy_eval = evaluate_policy(ev, inventory={}, inputs=inputs)
            self.assertFalse(policy_eval["accepted"])
            self.assertEqual(policy_eval["status"], "blocked")
            self.assertEqual(policy_eval["raw_lint_status"], "fail")
            self.assertIn("incomplete-preservation-inventory", policy_eval["blockers"])

            policy_bytes = canonical(policy_eval)
            policy_path.write_bytes(policy_bytes)
            self.assertLessEqual(policy_path.stat().st_size, 64 * 1024)
            data_policy = diagnostic_bytes(policy_path)
            self.assertEqual(data_policy, policy_bytes)

            # Neither identity nor acceptance was altered to fit size caps
            self.assertEqual(policy_eval["accepted"], False)
            self.assertEqual(ev["clean"], False)
            self.assertEqual(ev["status"], "fail")
            self.assertEqual(len(ev["error_records"]), 15)
        finally:
            for p in (diag_path, pretty_path, policy_path):
                try:
                    if p.exists():
                        p.unlink()
                except OSError:
                    pass


if __name__ == "__main__":
    unittest.main()
