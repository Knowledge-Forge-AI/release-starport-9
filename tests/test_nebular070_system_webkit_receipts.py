"""Receipt byte-domain and native-member boundaries for real thin payloads."""
from __future__ import annotations

import copy
import io
import tarfile
import unittest
from pathlib import Path

from rs9.nebular070_installed_smoke import verified_application_receipt_digest
from rs9.nebular070_system_webkit import validate_missing_runtime
from rs9.tf_pypi_archive import AdmissionError, canonical, sha256
from rs9.tf_pypi_consumer import _nebular_payload_member


class ReceiptIdentityTests(unittest.TestCase):
    def test_provider_version_definitions_are_bounded_and_structurally_checked(self):
        import struct
        from rs9.nebular070_system_webkit import _provider_version_definitions
        body = bytearray(512)
        body[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<Q", body, 40, 256)
        struct.pack_into("<HH", body, 58, 64, 3)
        strings = b"\0WEBKIT_TEST_1.0\0"
        body[64:64 + len(strings)] = strings
        struct.pack_into("<HHHHIII", body, 128, 1, 0, 2, 1, 0, 20, 0)
        struct.pack_into("<II", body, 148, 1, 0)
        struct.pack_into("<IIQQQQIIQQ", body, 320, 0, 3, 0, 0, 64, len(strings), 0, 0, 1, 0)
        struct.pack_into("<IIQQQQIIQQ", body, 384, 0, 0x6FFFFFFD, 0, 0, 128, 28, 1, 1, 4, 0)
        self.assertEqual(_provider_version_definitions(bytes(body)), ["WEBKIT_TEST_1.0"])
        absent = bytearray(body)
        struct.pack_into("<I", absent, 388, 0)
        self.assertEqual(_provider_version_definitions(bytes(absent)), [])
        for offset, value in ((148, 9999), (408, 9999), (424, 9), (428, 2), (144, 9999)):
            changed = bytearray(body)
            struct.pack_into("<I", changed, offset, value)
            with self.subTest(offset=offset), self.assertRaises(AdmissionError):
                _provider_version_definitions(bytes(changed))

    def test_native_execution_diagnostics_emit_only_closed_categories(self):
        from rs9.nebular070_installed_smoke import _native_execution_failure_code
        from rs9.tf_pypi_archive import fail
        self.assertEqual(_native_execution_failure_code({"timed_out": True}),
                         "NEBULAR_NATIVE_EXECUTION_TIMEOUT")
        for stderr, suffix in (("ERR_MODULE_NOT_FOUND at /private/example", "NODE_MODULE"),
                               ("ENOENT /private/example", "FILESYSTEM_MISSING"),
                               ("SyntaxError: private text", "NODE_SYNTAX")):
            self.assertEqual(_native_execution_failure_code({"stderr_token": stderr}),
                             "NEBULAR_NATIVE_EXECUTION_" + suffix)
        self.assertEqual(_native_execution_failure_code({"stderr_token": "unclassified private text"}),
                         "NEBULAR_NATIVE_EXECUTION")
        for code in ("NEBULAR_NATIVE_ENTRYPOINT", _native_execution_failure_code({"stderr_token": "SyntaxError"})):
            with self.assertRaises(AdmissionError) as caught:
                fail(code)
            self.assertEqual(caught.exception.code, "TF_PYPI_" + code)

    def test_failed_harness_reports_expose_only_closed_diagnostic_categories(self):
        import json
        from rs9.nebular070_installed_smoke import _native_execution_failure_code
        def summary(problems):
            return {"stdout_token": json.dumps({"label": "owned-run", "status": "fail",
                                                "problems": problems}), "stderr_token": ""}
        cases = [
            (["harness error: ENOENT /private/example"], "FILESYSTEM_MISSING"),
            (["required step app-shell failed: private payload"], "STEP_APP_SHELL"),
            (["application exit code 134 signal null"], "APPLICATION_EXIT"),
            (["persistent user state changed: /private/example"], "USER_STATE"),
            (["private unrecognized payload"], None),
        ]
        for problems, category in cases:
            expected = "NEBULAR_NATIVE_EXECUTION" + ("_" + category if category else "")
            self.assertEqual(_native_execution_failure_code(summary(problems)), expected)
        report = {"finalization": {"schema": "nebular.native-rc-finalization-v1",
                  "status": "failed", "phase": "pre-spawn", "exceptionFamily": "filesystem"}}
        self.assertEqual(_native_execution_failure_code({}, report=report),
                         "NEBULAR_NATIVE_EXECUTION_HARNESS_PRE_SPAWN_FILESYSTEM")
        report["finalization"]["phase"] = "/private/example"
        self.assertEqual(_native_execution_failure_code({}, report=report),
                         "NEBULAR_NATIVE_EXECUTION")
        self.assertEqual(_native_execution_failure_code({"stdout_token": "{", "stderr_token": ""}),
                         "NEBULAR_NATIVE_EXECUTION")

    def test_spawn_git_and_cleanup_failures_keep_closed_diagnostics(self):
        import errno
        import subprocess
        import traceback
        from types import SimpleNamespace
        from unittest.mock import patch
        from rs9.nebular070_installed_smoke import _native_execution_failure_code
        from rs9.tf_pypi_consumer import _nebular_run
        from rs9.tf_pypi_nebular070_publish import _git_output
        spawn_cases = [
            (errno.ENOENT, "MISSING"), (errno.ENOTDIR, "NOT_DIRECTORY"),
            (errno.EACCES, "PERMISSION"), (errno.EPERM, "PERMISSION"),
            (errno.ENOEXEC, "FORMAT"), (errno.EIO, "OS"), (None, "OS"),
        ]
        for number, suffix in spawn_cases:
            def broken(*args, **kwargs):
                raise OSError(number, "private", "/private/example")
            with self.subTest(errno=number), self.assertRaises(AdmissionError) as caught:
                _nebular_run(["missing"], {}, Path("."), (), 1, runner=broken)
            self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_NATIVE_EXECUTION_SPAWN_" + suffix)
            rendered = str(caught.exception) + repr(caught.exception) + "".join(traceback.format_exception(caught.exception))
            self.assertNotIn("/private/example", rendered)
        def subprocess_error(*args, **kwargs):
            raise subprocess.SubprocessError("/private/example")
        with self.assertRaises(AdmissionError) as caught:
            _nebular_run(["missing"], {}, Path("."), (), 1, runner=subprocess_error)
        self.assertEqual(caught.exception.code, "TF_PYPI_NEBULAR_NATIVE_EXECUTION_SPAWN_SUBPROCESS")
        self.assertNotIn("/private/example", "".join(traceback.format_exception(caught.exception)))
        git_cases = [
            ("fatal: detected dubious ownership in /private/example", "HOSTED_COMMIT", "HOSTED_COMMIT_OWNERSHIP"),
            ("fatal: not a git repository /private/example", "HOSTED_COMMIT", "HOSTED_COMMIT_REPOSITORY"),
            ("fatal: detected dubious ownership in /private/example", "SOURCE_LINEAGE", "SOURCE_LINEAGE"),
            ("unrecognized /private/example", "HOSTED_COMMIT", "HOSTED_COMMIT"),
            (b"not a git repository /private/example", "HOSTED_COMMIT", "HOSTED_COMMIT"),
            (None, "HOSTED_COMMIT", "HOSTED_COMMIT"),
        ]
        for stderr, code, expected in git_cases:
            with self.subTest(git_code=code, stderr_type=type(stderr).__name__), patch(
                    "rs9.tf_pypi_nebular070_publish.subprocess.run",
                    return_value=SimpleNamespace(returncode=128, stdout="", stderr=stderr)):
                with self.assertRaises(AdmissionError) as caught:
                    _git_output(Path("."), ["rev-parse", "HEAD"], code)
                self.assertEqual(caught.exception.code, "TF_PYPI_" + expected)
                rendered = str(caught.exception) + repr(caught.exception) + "".join(traceback.format_exception(caught.exception))
                self.assertNotIn("/private/example", rendered)
        cases = [
            ({"forced_cleanup": True}, "FORCED_CLEANUP"),
            ({"cleanup_known": False}, "CLEANUP_UNOBSERVED"),
            ({"output_complete": False}, "OUTPUT_INCOMPLETE"),
            ({"exit_code": 127}, "EXIT_COMMAND_NOT_FOUND"),
            ({"exit_code": 126}, "EXIT_PERMISSION"),
            ({"exit_code": 1}, "EXIT_NONZERO"),
            ({"exit_code": -9}, "SIGNAL"),
            ({"exit_code": 127, "forced_cleanup": True}, "EXIT_COMMAND_NOT_FOUND"),
            ({"exit_code": -9, "forced_cleanup": True}, "FORCED_CLEANUP"),
            ({"exit_code": 1, "cleanup_known": False, "output_complete": False}, "CLEANUP_UNOBSERVED"),
            ({"stderr_token": "ENOENT /private/example", "forced_cleanup": True}, "FILESYSTEM_MISSING"),
        ]
        for process, suffix in cases:
            with self.subTest(process=process):
                self.assertEqual(_native_execution_failure_code(process), "NEBULAR_NATIVE_EXECUTION_" + suffix)
        for value in (0, 256, -256, True, 1.0, "127", None):
            with self.subTest(invalid_exit_type=type(value).__name__, invalid_exit=value):
                self.assertEqual(_native_execution_failure_code({"exit_code": value}), "NEBULAR_NATIVE_EXECUTION")
        self.assertEqual(_native_execution_failure_code({}), "NEBULAR_NATIVE_EXECUTION")

    def test_missing_runtime_cli_keeps_commit_and_run_coordinate_refusals(self):
        import contextlib
        from unittest.mock import patch
        from rs9.tf_pypi_nebular070_publish import main
        from rs9.wheel_nebular_successor import SYSTEM_WEBKIT_PROFILE, gate1_profile_record
        cases = [
            ("b" * 40, "1", "123", "HOSTED_COMMIT_MISMATCH"),
            ("a" * 40, "2", "123", "HOSTED_COMMIT_RUN_COORDINATES"),
            ("a" * 40, "1", "bad", "HOSTED_COMMIT_RUN_COORDINATES"),
            ("b" * 40, "2", "bad", "HOSTED_COMMIT_MISMATCH"),
        ]
        for expected, attempt, run_id, code in cases:
            stderr = io.StringIO()
            with self.subTest(code=code, attempt=attempt, run=run_id), contextlib.ExitStack() as stack:
                stack.enter_context(patch("rs9.tf_pypi_nebular070_publish._require_real_directory", return_value=Path(".")))
                stack.enter_context(patch("rs9.tf_pypi_nebular070_publish._validate_bundle_file_set"))
                stack.enter_context(patch("rs9.tf_pypi_nebular070_publish._read_json_object",
                                         return_value={"profile": gate1_profile_record(SYSTEM_WEBKIT_PROFILE)}))
                stack.enter_context(patch("rs9.tf_pypi_nebular070_publish.repo_root", return_value=Path(".")))
                stack.enter_context(patch("rs9.tf_pypi_nebular070_publish._git_output", side_effect=["a" * 40, "c" * 40]))
                check = stack.enter_context(patch("rs9.nebular070_system_webkit.check_missing_runtime"))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                result = main(["check-system-webkit-missing", "--bundle", ".", "--target", "linux-x64-gnu",
                               "--work", "unused", "--output", "unused.json", "--expected-commit", expected,
                               "--run-id", run_id, "--run-attempt", attempt])
                self.assertEqual(result, 1)
                self.assertEqual(stderr.getvalue().strip(), "TF_PYPI_" + code)
                check.assert_not_called()

    def test_source_receipt_and_retained_copy_have_distinct_bound_bytes(self):
        original = b'{\n  "status": "pass"\n}'
        expected = sha256(original)
        self.assertEqual(verified_application_receipt_digest(original, expected), expected)
        self.assertEqual(verified_application_receipt_digest(original + b"\n", expected), expected)
        for changed in (original + b"\n\n", original.replace(b"pass", b"fail"), b'{"status":"pass"}'):
            with self.subTest(changed=changed), self.assertRaises(AdmissionError):
                verified_application_receipt_digest(changed, expected)

    def test_native_sidecar_can_exceed_the_compressed_archive_bound(self):
        # Actual released sidecars are 116-120 MiB. A compressible 65 MiB
        # fixture exercises the old 64 MiB refusal without a large archive.
        data = b"x" * (65 * 1024 * 1024)
        member = {"path": "payload/bin/service", "size": len(data), "sha256": sha256(data)}
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            info = tarfile.TarInfo(member["path"])
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        self.assertEqual(_nebular_payload_member(Path("."), output.getvalue(), member), data)
        with self.assertRaises(AdmissionError):
            _nebular_payload_member(Path("."), output.getvalue(), {**member, "size": 257 * 1024 * 1024})

    def test_missing_runtime_receipt_cannot_move_between_hosts_or_wheels(self):
        source = {"commit": "a" * 40, "tree": "b" * 40}
        wheel = {"sha256": "c" * 64, "tag": "py3-none-linux_x86_64"}
        def process(code):
            return {"exit_code": code, "signal": None, "stdout_sha256": sha256(b""),
                    "stderr_sha256": sha256(b""), "cleanup_known": True,
                    "output_complete": True, "forced_cleanup": False}
        body = {
            "schema": "rs9.nebular070-system-webkit-missing-runtime.v1", "status": "passed",
            "target": "linux-x64-gnu", "source": source, "run": {"id": "17", "attempt": "1"},
            "host_observation_identity": "d" * 64, "host_class": "bookworm-floor",
            "wheel_sha256": wheel["sha256"], "wheel_tag": wheel["tag"],
            "soname": "libwebkit2gtk-4.1.so.0", "unavailable": process(2), "install": process(0),
            "normal_entrypoint": process(1), "uninstall": process(0),
            "payload_materialized": False, "library_environment_modified": False,
        }
        def sign(value):
            return {**value, "identity": sha256(canonical(value))}
        def validate(value, **kwargs):
            return validate_missing_runtime(value, target="linux-x64-gnu", source=source,
                run_id="17", run_attempt="1", wheel=wheel, host_identity=kwargs.get("host", "d" * 64))
        validate(sign(body))
        for field, changed in (("wheel_sha256", "f" * 64), ("host_class", "ubuntu-newer"),
                               ("payload_materialized", True), ("library_environment_modified", True)):
            with self.subTest(field=field), self.assertRaises(AdmissionError):
                validate(sign({**body, field: changed}))
        with self.assertRaises(AdmissionError):
            validate(sign(body), host="e" * 64)
        changed = copy.deepcopy(body)
        changed["normal_entrypoint"]["exit_code"] = 0
        with self.assertRaises(AdmissionError):
            validate(sign(changed))
