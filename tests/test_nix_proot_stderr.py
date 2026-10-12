"""Tests for bounded secret-safe stderr diagnostic evaluation."""

from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from unittest.mock import patch

from rs9.nix_proot_stderr import (
    MAX_STREAM_BYTES,
    MAX_EXCERPT_BYTES,
    PUBLIC_GUEST_PATHS,
    redact_paths_and_privacy,
    stream_diagnostic,
)


class NixProotStderrTests(unittest.TestCase):
    def test_invalid_utf8_withholds_excerpt(self):
        raw = b"proot error: \x80\xff\xfe\xca\xfe binary corruption\n"
        res = stream_diagnostic(
            raw,
            stage="display-only",
            argv_sha256="abc123",
            returncode=1,
        )
        self.assertFalse(res["utf8_valid"])
        self.assertEqual(res["raw_bytes"], len(raw))
        self.assertEqual(res["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(res["excerpt_status"], "withheld")
        self.assertNotIn("excerpt", res)
        self.assertTrue(res["complete"])

    def test_control_characters_withholds_excerpt(self):
        for ctrl_byte in (b"\x00", b"\x07", b"\x1b[31m"):
            raw = b"bwrap: creating new namespace: Operation not permitted " + ctrl_byte + b"\n"
            res = stream_diagnostic(
                raw,
                stage="combined-pinned-python",
                argv_sha256="def456",
                returncode=1,
            )
            self.assertTrue(res["control"])
            self.assertTrue(res["control_flag"])
            self.assertEqual(res["excerpt_status"], "withheld")
            self.assertNotIn("excerpt", res)

    def test_truncated_and_size_limits_complete_flag(self):
        raw = b"bwrap: creating new namespace: Operation not permitted\n"
        res_trunc = stream_diagnostic(
            raw,
            stage="display-only",
            argv_sha256="aaa",
            returncode=1,
            truncated=True,
        )
        self.assertFalse(res_trunc["complete"])
        self.assertEqual(res_trunc["excerpt_status"], "withheld")
        self.assertNotIn("excerpt", res_trunc)

        oversize_raw = b"bwrap: creating new namespace: Operation not permitted\n" * 100
        self.assertGreater(len(oversize_raw), MAX_STREAM_BYTES)
        res_oversize = stream_diagnostic(
            oversize_raw,
            stage="display-only",
            argv_sha256="bbb",
            returncode=1,
        )
        self.assertFalse(res_oversize["complete"])
        self.assertEqual(res_oversize["excerpt_status"], "withheld")

        for err, token in (
            ("timeout", "timeout"),
            ("output-limit", "output-limit"),
            ("spawn-failed", "spawn-failed"),
        ):
            res_err = stream_diagnostic(
                b"",
                stage="display-only",
                argv_sha256="ccc",
                returncode=None,
                run_error=err,
            )
            self.assertFalse(res_err["complete"])
            self.assertEqual(res_err["cause_token"], token)
            self.assertEqual(res_err["excerpt_status"], "withheld")

    def test_conflicting_mixed_causal_origins_rejected(self):
        raw = (
            b"bwrap: creating new namespace: Operation not permitted\n"
            b"xvfb-run: line 83: getopt: command not found\n"
        )
        res = stream_diagnostic(
            raw,
            stage="combined-pinned-python",
            argv_sha256="mixed",
            returncode=1,
        )
        self.assertEqual(res["cause_token"], "conflicting")
        self.assertIsNone(res["origin"])
        self.assertIn("bwrap", res["origins"])
        self.assertIn("xvfb-run", res["origins"])
        self.assertEqual(res["excerpt_status"], "withheld")
        self.assertNotIn("excerpt", res)

    def test_credentials_redaction_and_withholding(self):
        priv_key = (
            b"-----" b"BEGIN PRIVATE KEY-----\n"
            b"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD3f8rX9Z4m9fQ2\n"
            b"-----END PRIVATE KEY-----\n"
        )
        res_key = stream_diagnostic(
            priv_key,
            stage="display-only",
            argv_sha256="sec1",
            returncode=1,
        )
        self.assertEqual(res_key["excerpt_status"], "withheld")
        self.assertNotIn("excerpt", res_key)
        self.assertNotIn("PRIVATE KEY", json.dumps(res_key))

        token_raw = b"fatal error: failed to authenticate with token ghp_" + b"0" * 36 + b"\n"
        res_token = stream_diagnostic(
            token_raw,
            stage="display-only",
            argv_sha256="sec2",
            returncode=1,
        )
        self.assertEqual(res_token["excerpt_status"], "withheld")
        self.assertNotIn("excerpt", res_token)
        self.assertNotIn("ghp_", json.dumps(res_token))

    def test_path_redaction_and_preservation(self):
        closure = (
            "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-valid-pkg-1.0",
        )
        host_binds = (
            "/host/workspace/app",
        )
        text = (
            "cannot open /host/workspace/app/config.json: No such file or directory\n"
            "failed to load /" "Users/local-user/private_data\n"
            "missing /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-outside/bin/tool\n"
            "executing /nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-valid-pkg-1.0/bin/tool\n"
            "reading /etc/dbus-1/session.conf\n"
            "device /dev/null\n"
            "nonce 0123456789abcdef0123456789abcdef\n"
            "process pid 12345 uid 1000\n"
            "dbus-daemon[6789]: started\n"
        )
        redacted = redact_paths_and_privacy(text, host_binds=host_binds, closure=closure)

        self.assertNotIn("/host/workspace/app", redacted)
        self.assertIn("<host-bind>", redacted)
        self.assertNotIn("/" + "Users/local-user/private_data", redacted)
        self.assertNotIn("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-outside", redacted)
        self.assertIn("<path>", redacted)

        self.assertIn("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-valid-pkg-1.0/bin/tool", redacted)
        self.assertIn("/etc/dbus-1/session.conf", redacted)
        self.assertIn("/dev/null", redacted)

        self.assertNotIn("0123456789abcdef0123456789abcdef", redacted)
        self.assertIn("<hex>", redacted)
        self.assertNotIn("12345", redacted)
        self.assertIn("<pid>", redacted)
        self.assertNotIn("1000", redacted)
        self.assertIn("<uid>", redacted)
        self.assertNotIn("[6789]", redacted)
        self.assertIn("[<pid>]", redacted)

    def test_serialized_credential_scan_safety(self):
        raw = b"bwrap: creating new namespace: Operation not permitted\n"
        with patch("rs9.nix_proot_stderr.scan_for_credentials") as mock_scan:
            from rs9.errors import ContractError
            def side_effect(arg):
                if '"stage": "unsafe"' in arg:
                    raise ContractError("CREDENTIAL_DETECTED", "Leak detected")
            mock_scan.side_effect = side_effect
            res = stream_diagnostic(
                raw,
                stage="unsafe",
                argv_sha256="abc",
                returncode=1,
            )
            self.assertEqual(res["excerpt_status"], "withheld")
            self.assertNotIn("excerpt", res)

    def test_no_inferred_cause_from_exit_127_or_sha(self):
        res_unknown_output = stream_diagnostic(
            b"arbitrary unrecognized failure output\n",
            stage="baseline-original-smoke",
            argv_sha256="deadbeef",
            returncode=127,
        )
        self.assertEqual(res_unknown_output["raw_returncode"], 127)
        self.assertEqual(res_unknown_output["cause_token"], "unknown")
        self.assertIsNone(res_unknown_output["origin"])
        self.assertEqual(res_unknown_output["excerpt_status"], "withheld")
        self.assertNotIn("excerpt", res_unknown_output)

        res_empty = stream_diagnostic(
            b"",
            stage="baseline-original-smoke",
            argv_sha256="deadbeef",
            returncode=127,
        )
        self.assertEqual(res_empty["raw_returncode"], 127)
        self.assertEqual(res_empty["cause_token"], "unknown")
        self.assertIsNone(res_empty["origin"])
        self.assertEqual(res_empty["excerpt_status"], "withheld")

    def test_ordinary_exit_255_not_inferred(self):
        res = stream_diagnostic(
            b"custom process exit message\n",
            stage="baseline-original-main",
            argv_sha256="cafebabe",
            returncode=255,
        )
        self.assertEqual(res["raw_returncode"], 255)
        self.assertEqual(res["exit_code"], 255)
        self.assertIsNone(res["signal"])
        self.assertEqual(res["cause_token"], "unknown")
        self.assertEqual(res["excerpt_status"], "withheld")
        self.assertNotIn("excerpt", res)

    def test_proot_warning_advisory_ignored_for_cause(self):
        raw = (
            b"proot warning: can't chdir('/host/work'): No such file or directory\n"
            b"bwrap: creating new namespace: Operation not permitted\n"
        )
        res = stream_diagnostic(
            raw,
            stage="combined-pinned-python",
            argv_sha256="prov1",
            returncode=1,
            host_binds=("/host/work",),
        )
        self.assertEqual(res["origin"], "bwrap")
        self.assertEqual(res["origins"], ["bwrap"])
        self.assertEqual(res["cause_token"], "userns-denied")
        self.assertEqual(res["errno_token"], "EPERM")
        self.assertEqual(res["excerpt_status"], "present")
        self.assertIn("excerpt", res)
        self.assertIn("<host-bind>", res["excerpt"])
        self.assertIn("bwrap: creating new namespace: Operation not permitted", res["excerpt"])

    def test_proot_warning_unknown_content_withheld(self):
        raw = (
            b"proot warning: strange unknown internal error 4294967295\n"
            b"bwrap: creating new namespace: Operation not permitted\n"
        )
        res = stream_diagnostic(
            raw,
            stage="combined-pinned-python",
            argv_sha256="prov2",
            returncode=1,
        )
        self.assertEqual(res["cause_token"], "userns-denied")
        self.assertEqual(res["origin"], "bwrap")
        self.assertEqual(res["excerpt_status"], "withheld")
        self.assertNotIn("excerpt", res)

    def test_python_traceback_continuation_origin_inheritance(self):
        closure = ("/nix/store/11111111111111111111111111111111-python3-3.13.12",)
        host_binds = ("/host/code",)
        raw = (
            b"Traceback (most recent call last):\n"
            b'  File "/host/code/runner.py", line 42, in <module>\n'
            b"    run()\n"
            b'  File "/nix/store/11111111111111111111111111111111-python3-3.13.12/lib/runpy.py", line 198, in run\n'
            b"    exec(code)\n"
            b"FileNotFoundError: [Errno 2] No such file or directory: '/etc/dbus-1/session.conf'\n"
        )
        res = stream_diagnostic(
            raw,
            stage="dbus-only",
            argv_sha256="py1",
            returncode=1,
            closure=closure,
            host_binds=host_binds,
        )
        self.assertEqual(res["origin"], "python")
        self.assertEqual(res["origins"], ["python"])
        self.assertEqual(res["cause_token"], "guest-file-missing")
        self.assertEqual(res["errno_token"], "ENOENT")
        self.assertEqual(res["excerpt_status"], "present")
        self.assertIn("excerpt", res)
        self.assertIn("<host-bind>", res["excerpt"])
        self.assertIn("/nix/store/11111111111111111111111111111111-python3-3.13.12", res["excerpt"])
        self.assertIn("/etc/dbus-1/session.conf", res["excerpt"])

    def test_ordinary_line_cannot_acquire_origin(self):
        raw = (
            b"Traceback (most recent call last):\n"
            b'  File "test.py", line 1, in <module>\n'
            b"    pass\n"
            b"ValueError: bad value\n"
            b"ordinary unknown line that cannot acquire origin\n"
        )
        res = stream_diagnostic(
            raw,
            stage="dbus-only",
            argv_sha256="py2",
            returncode=1,
        )
        self.assertEqual(res["excerpt_status"], "withheld")
        self.assertNotIn("excerpt", res)

    def test_dbus_observed_text_redacted_without_recollection_template(self):
        raw = b"dbus-daemon[1234]: cannot open /etc/dbus-1/session.conf: No such file or directory\n"
        res = stream_diagnostic(
            raw,
            stage="dbus-only",
            argv_sha256="dbus1",
            returncode=1,
        )
        self.assertEqual(res["origin"], "dbus-daemon")
        self.assertEqual(res["cause_token"], "unclassified")
        self.assertEqual(res["errno_token"], "ENOENT")
        self.assertEqual(res["excerpt_status"], "present")
        self.assertEqual(res['excerpt_basis'], 'redacted-observed-text')
        self.assertNotIn('/etc/dbus-1/session.conf', res['excerpt'])
        self.assertNotIn('1234', res['excerpt'])

    def test_circular_include_cause_requires_safe_observed_substring(self):
        raw = b"dbus-daemon[42]: Circular inclusion of file '/etc/dbus-1/session.conf'\n"
        result = stream_diagnostic(raw, stage='dbus-only', argv_sha256='a'*64, returncode=1)
        self.assertEqual(result['cause_token'], 'dbus-config-circular-include')
        self.assertEqual(result['cause_basis'], 'observed-substring')
        self.assertIn('<path>', result['excerpt'])
        for unsafe in (raw + b'unknown continuation\n', raw.replace(b'Circular', b'circular'),
                       raw + b'dbus-daemon[42]: password=plain\n',
                       b'dbus-daemon[42]: ' + b'x'*201 + b'\n',
                       raw + b'dbus-daemon[42]: \tinvalid\n'):
            with self.subTest(raw_sha256=hashlib.sha256(unsafe).hexdigest()):
                result = stream_diagnostic(unsafe, stage='dbus-only', argv_sha256='a'*64, returncode=1)
                self.assertNotEqual(result['cause_token'], 'dbus-config-circular-include')
                self.assertNotIn('cause_basis', result)

    def test_dbus_unrecognised_unicode_and_non_dbus_stage_withhold(self):
        for raw in (b'dbus-daemon[42]: failure\nprivate continuation\n',
                    'dbus-daemon[42]: \u00e9chec\n'.encode()):
            result = stream_diagnostic(raw, stage='dbus-only', argv_sha256='a'*64, returncode=1)
            self.assertNotIn('excerpt', result)
        result = stream_diagnostic(b'dbus-daemon[42]: failure\n', stage='display-only',
                                   argv_sha256='a'*64, returncode=1)
        self.assertNotIn('excerpt', result)

    def test_oversize_excerpt_withheld(self):
        line = "xvfb-run: line 83: getopt: command not found " + ("A" * 50) + "\n"
        raw = (line * 15).encode("utf-8")
        self.assertLessEqual(len(raw), MAX_STREAM_BYTES)
        self.assertGreater(len(raw), MAX_EXCERPT_BYTES)
        res = stream_diagnostic(
            raw,
            stage="display-only",
            argv_sha256="big",
            returncode=127,
        )
        self.assertTrue(res["complete"])
        self.assertEqual(res["excerpt_status"], "withheld")
        self.assertNotIn("excerpt", res)

    def test_import_guards_launch_nothing(self):
        with patch("subprocess.run") as mock_run, patch("subprocess.Popen") as mock_popen:
            res = stream_diagnostic(
                b"bwrap: creating new namespace: Operation not permitted\n",
                stage="display-only",
                argv_sha256="guard",
                returncode=1,
            )
            mock_run.assert_not_called()
            mock_popen.assert_not_called()
            self.assertEqual(res["cause_token"], "userns-denied")

    def test_allow_excerpt_false(self):
        raw = b"bwrap: creating new namespace: Operation not permitted\n"
        res = stream_diagnostic(
            raw,
            stage="display-only",
            argv_sha256="noexc",
            returncode=1,
            allow_excerpt=False,
        )
        self.assertEqual(res["excerpt_status"], "withheld")
        self.assertNotIn("excerpt", res)
        self.assertEqual(res["cause_token"], "userns-denied")

    def test_incomplete_causal_bytes_never_infer_cause(self):
        raw = b"proot error: ptrace: Operation not permitted\n"
        for kwargs in ({"truncated": True}, {"run_error": "timeout"}):
            result = stream_diagnostic(raw, stage="dbus-only", argv_sha256="a"*64, returncode=127, **kwargs)
            self.assertFalse(result["complete"])
            self.assertIsNone(result["errno_token"])
            self.assertNotEqual(result["cause_token"], "ptrace-denied")
            self.assertNotIn("excerpt", result)

    def test_unknown_origins_private_payload_and_unicode_controls_are_withheld(self):
        for raw in (b"private-user: private-command: command not found\n",
                    "bwrap: creating new namespace: Operation not permitted\u202e".encode(),
                    b"bwrap: creating new namespace: Operation not permitted password=plain\n"):
            result=stream_diagnostic(raw,stage="dbus-only",argv_sha256="a"*64,returncode=127)
            self.assertNotIn("excerpt",result)
            self.assertNotIn("private-user",json.dumps(result))

    def test_ordered_dbus_chain_is_unclassified_and_proot_error_conflicts(self):
        raw=b"dbus-daemon[123]: failure\ndbus-run-session: failure\n"
        result=stream_diagnostic(raw,stage="dbus-only",argv_sha256="a"*64,returncode=127)
        self.assertEqual(result["cause_token"],"unclassified")
        result=stream_diagnostic(raw+b"proot error: failure\n",stage="dbus-only",argv_sha256="a"*64,returncode=127)
        self.assertEqual(result["cause_token"],"conflicting")
        self.assertNotIn("excerpt",result)

    def test_same_tool_conflicting_errno_is_not_a_single_cause(self):
        result=stream_diagnostic(b"proot error: No such file or directory\nproot error: Permission denied\n",
            stage="dbus-only",argv_sha256="a"*64,returncode=127)
        self.assertEqual(result["cause_token"],"conflicting")
        self.assertIsNone(result["errno_token"])
        self.assertNotIn("excerpt",result)


if __name__ == "__main__":
    unittest.main()
