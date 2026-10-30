"""Synthetic proof domains for universal and historical platform launchers."""
import copy
import unittest

from rs9 import nebular070_installed_smoke as smoke
from rs9.tf_pypi_archive import AdmissionError, canonical, sha256
import tests.test_nebular070_system_webkit_consumer as fixtures


class UniversalPreflightTests(unittest.TestCase):
    def proof(self):
        value = fixtures.SystemWebKitConsumerTests._preflight()
        value.update(schema="rs9.nebular070-system-webkit-preflight.v2",
                     distribution="universal-launcher")
        value["wheel"]["tag"] = "py3-none-any"
        return self.sign(value)

    @staticmethod
    def sign(value):
        value = copy.deepcopy(value)
        value.pop("identity", None)
        return {**value, "identity": sha256(canonical(value))}

    def test_universal_proof_requires_explicit_distribution_domain(self):
        proof = self.proof()
        checked = smoke.validate_system_webkit_preflight(
            proof, target="linux-x64-gnu", distribution="universal-launcher")
        self.assertEqual(checked, proof)
        with self.assertRaises(AdmissionError):
            smoke.validate_system_webkit_preflight(proof, target="linux-x64-gnu")
        with self.assertRaises(AdmissionError):
            smoke._summary_system_webkit(proof, target="linux-x64-gnu")
        self.assertEqual(smoke._summary_system_webkit(
            proof, target="linux-x64-gnu", distribution="universal-launcher"), proof)

    def test_universal_domain_rejects_platform_proof_and_tag(self):
        with self.assertRaises(AdmissionError):
            smoke.validate_system_webkit_preflight(
                fixtures.SystemWebKitConsumerTests._preflight(),
                target="linux-x64-gnu", distribution="universal-launcher")
        proof = self.proof()
        proof["wheel"]["tag"] = "py3-none-linux_x86_64"
        with self.assertRaises(AdmissionError):
            smoke.validate_system_webkit_preflight(
                self.sign(proof), target="linux-x64-gnu", distribution="universal-launcher")

    def test_proof_distribution_and_identity_cannot_be_relabelled(self):
        for change in ({"distribution": "platform-wheel"},
                       {"schema": smoke.SYSTEM_WEBKIT_PREFLIGHT_SCHEMA},
                       {"identity": "0" * 64}):
            with self.subTest(fields=tuple(change)), self.assertRaises(AdmissionError):
                smoke.validate_system_webkit_preflight(
                    {**self.proof(), **change}, target="linux-x64-gnu",
                    distribution="universal-launcher")

    def test_old_platform_domain_still_rejects_any_tag(self):
        value = fixtures.SystemWebKitConsumerTests._preflight()
        value["wheel"]["tag"] = "py3-none-any"
        with self.assertRaises(AdmissionError):
            smoke.validate_system_webkit_preflight(self.sign(value), target="linux-x64-gnu")

    def test_producer_defaults_stay_v1_and_universal_is_explicit_v2(self):
        old = fixtures.SystemWebKitConsumerTests._preflight()
        args = dict(target="linux-x64-gnu", wheel_sha256="1" * 64,
                    wheel_tag="py3-none-linux_x86_64", payload_archive_sha256="2" * 64,
                    payload_manifest_sha256="3" * 64, source=old["source"],
                    run_id="17", run_attempt="1", host=old["host"], provider=old["provider"])
        process = dict(exit_code=0, signal=None, stdout_token="", stderr_token="",
                       stdout_sha256=sha256(b""), stderr_sha256=sha256(b""),
                       cleanup_known=True, output_complete=True, forced_cleanup=False)
        baseline = smoke.produce_system_webkit_preflight(process=process, **args)
        self.assertEqual(baseline["schema"], smoke.SYSTEM_WEBKIT_PREFLIGHT_SCHEMA)
        self.assertNotIn("distribution", baseline)
        universal = smoke.produce_system_webkit_preflight(
            process=process, **{**args, "wheel_tag": "py3-none-any"},
            distribution="universal-launcher")
        self.assertEqual(universal["schema"], "rs9.nebular070-system-webkit-preflight.v2")
        self.assertEqual(universal["distribution"], "universal-launcher")
        self.assertEqual(smoke.validate_system_webkit_preflight(
            universal, target="linux-x64-gnu", distribution="universal-launcher"), universal)
