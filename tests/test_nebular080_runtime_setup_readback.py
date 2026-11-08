"""Exercise the production readback for the launcher's three setup envelopes."""
import copy
import hashlib
import json
import unittest

from rs9 import nebular080_universal_consumer as consumer
from rs9 import nebular080_universal_missing as missing
from rs9 import nebular080_host_observation as observation
from rs9 import nebular080_manylinux as facade
from rs9 import nebular080_payload as payload
from rs9.nebular080_universal_profile import SCHEMAS
from rs9.errors import ContractError


def sha(data):
    return hashlib.sha256(data).hexdigest()


def process(stdout=b"", stderr=b"", exit_code=0):
    return {
        "exit_code": exit_code, "signal": None,
        "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr),
        "duration_ms": 1, "timed_out": False, "output_limit_exceeded": False,
        "cleanup_known": True, "output_complete": True, "forced_cleanup": False,
    }


class RuntimeSetupReadbackTests(unittest.TestCase):
    def setUp(self):
        self.target = "linux-x64-gnu"
        self.spec = {"asset": {"size": 17, "sha256": "a" * 64}, "manifest_sha256": "b" * 64}
        self.setup = {
            "schema": SCHEMAS["runtime_setup"], "status": "passed", "target": self.target,
            "archive_sha256": "a" * 64, "archive_bytes": 17, "manifest_sha256": "b" * 64,
            "cold_refusal": process(stderr=missing.MISSING_LINE.encode(), exit_code=1),
            "explicit_setup": process(stdout=self.stdout(True)),
            "offline_reuse": process(stdout=self.stdout(False)),
            "archive_unchanged": True, "publication_admitted": False,
        }

    def stdout(self, downloaded, **changes):
        body = {
            "schema": "theme-forge-nebular-fusion.runtime-install.v1",
            "version": "0.8.0", "target": self.target,
            "archive_sha256": "a" * 64, "archive_bytes": 17, "manifest_sha256": "b" * 64,
            "downloaded": downloaded,
            "redirect_hosts": ["release-assets.githubusercontent.com"] if downloaded else [],
        }
        body.update(changes)
        return (json.dumps(body, sort_keys=True) + "\n").encode()

    def validate(self, value):
        return consumer._validate_runtime_setup(value, self.spec, target=self.target)

    def test_production_readback_accepts_all_three_exact_envelopes(self):
        self.assertEqual(self.validate(self.setup), self.setup)

    def test_cold_refusal_requires_missing_message_and_empty_stdout(self):
        for key in ("stdout_sha256", "stderr_sha256"):
            value = copy.deepcopy(self.setup)
            value["cold_refusal"][key] = "0" * 64
            with self.subTest(key=key), self.assertRaises(ContractError):
                self.validate(value)

    def test_download_readback_binds_download_flag_and_redirect_host(self):
        for body in (self.stdout(False), self.stdout(True, redirect_hosts=["other.example"]),
                     self.stdout(True, archive_sha256="c" * 64)):
            value = copy.deepcopy(self.setup)
            value["explicit_setup"]["stdout_sha256"] = sha(body)
            with self.subTest(body_sha256=sha(body)), self.assertRaises(ContractError):
                self.validate(value)

    def test_offline_readback_requires_cache_reuse_without_redirects(self):
        for body in (self.stdout(True), self.stdout(False, redirect_hosts=["release-assets.githubusercontent.com"])):
            value = copy.deepcopy(self.setup)
            value["offline_reuse"]["stdout_sha256"] = sha(body)
            with self.subTest(body_sha256=sha(body)), self.assertRaises(ContractError):
                self.validate(value)

    def test_setup_and_offline_require_empty_stderr(self):
        for stage in ("explicit_setup", "offline_reuse"):
            value = copy.deepcopy(self.setup)
            value[stage]["stderr_sha256"] = sha(b"unexpected progress\n")
            with self.subTest(stage=stage), self.assertRaises(ContractError):
                self.validate(value)

    def test_each_process_keeps_closed_shape_and_success_flags(self):
        for stage in ("cold_refusal", "explicit_setup", "offline_reuse"):
            for key, replacement in (("extra", True), ("cleanup_known", False),
                                     ("exit_code", True), ("timed_out", True),
                                     ("exit_code", 0 if stage == "cold_refusal" else 1),
                                     ("signal", "SIGTERM"), ("output_limit_exceeded", True),
                                     ("output_complete", False), ("forced_cleanup", True),
                                     ("stdout_sha256", "invalid")):
                value = copy.deepcopy(self.setup)
                value[stage][key] = replacement
                with self.subTest(stage=stage, key=key), self.assertRaises(ContractError):
                    self.validate(value)

    def test_archive_identity_and_closed_schema_are_required(self):
        for key, replacement in (("archive_sha256", "c" * 64), ("archive_bytes", 18),
                                 ("manifest_sha256", "c" * 64), ("schema", "old"),
                                 ("status", "failed"), ("target", "linux-arm64-gnu"),
                                 ("archive_unchanged", False),
                                 ("publication_admitted", True), ("extra", None)):
            value = copy.deepcopy(self.setup)
            value[key] = replacement
            with self.subTest(key=key), self.assertRaises(ContractError):
                self.validate(value)
        with self.assertRaises(ContractError):
            self.validate(None)

    def test_missing_owner_and_compatibility_facade_share_exact_target_table(self):
        self.assertIs(missing.LINUX_TARGETS, payload.LINUX_TARGETS)
        self.assertIs(facade.LINUX_TARGETS, payload.LINUX_TARGETS)
        self.assertIs(observation.LINUX_TARGETS, payload.LINUX_TARGETS)


if __name__ == "__main__":
    unittest.main()
