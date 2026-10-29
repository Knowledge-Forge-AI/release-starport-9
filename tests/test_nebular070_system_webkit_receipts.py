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
