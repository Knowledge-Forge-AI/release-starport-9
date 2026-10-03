import copy
import unittest

from rs9.errors import ContractError
from rs9.observation import observe, validate_observation
from rs9.records import validate_rfc3339_utc, validate_sanitized_string

DEST = {"id": "synthetic", "adapter": "registry", "mode": "direct"}
SUBJECT = {"package": "example", "version": "1.0", "revision": None}


class ObservationTests(unittest.TestCase):
    def build(self, **changes):
        readback = {"authenticated": True, "transport": "ok", "presence": "present", "components": {"artifact": "a" * 64},
                    "content_identity_sha256": "b" * 64, "level": "full"}
        readback.update(changes)
        return observe(DEST, SUBJECT, {"artifact": "a" * 64}, "b" * 64, readback=readback,
                       source="synthetic-fixture", observed_at="2026-10-03T12:00:00Z")

    def test_all_states_and_no_inferred_absence(self):
        self.assertEqual(self.build()["state"], "exact")
        self.assertEqual(self.build(authenticated=False)["state"], "unknown")
        self.assertEqual(self.build(transport="unreachable", presence="absent")["state"], "unreachable")
        self.assertEqual(self.build(presence="unknown")["state"], "unknown")
        self.assertEqual(self.build(presence="absent", components={}, content_identity_sha256=None)["state"], "absent")
        self.assertEqual(self.build(components={})["state"], "incomplete")
        self.assertEqual(self.build(components={}, content_identity_sha256="c" * 64)["state"], "conflict")
        self.assertEqual(self.build(components={"artifact": "c" * 64})["state"], "conflict")
        self.assertEqual(self.build(content_identity_sha256=None)["state"], "incomplete")
        self.assertEqual(self.build(level="metadata")["state"], "incomplete")
        self.assertEqual(self.build(level="none")["state"], "unknown")

    def test_forged_verdict_and_subject_rejected(self):
        obs = self.build(components={})
        obs["state"] = "exact"
        with self.assertRaises(ContractError): validate_observation(obs)
        with self.assertRaises(ContractError): validate_observation(self.build(), subject={**SUBJECT, "version": "2"})
        with self.assertRaises(ContractError): self.build(presence="absent")
        with self.assertRaises(ContractError): self.build(transport="network-error")

    def test_record_sanitization_and_real_calendar(self):
        for value in ("https://user:secret@example.com", "https://example.com?key=value", "https://example.com#fragment", "bad\nvalue", "/" + "Users" + "/operator/key"):
            with self.assertRaises(ContractError): validate_sanitized_string(value)
        for value in ("2025-02-29T12:00:00Z", "2026-10-03T12:00:00", "2026-10-03T12:00:00+01:00"):
            with self.assertRaises(ContractError): validate_rfc3339_utc(value)

    def test_explicit_source_time_and_diagnostics_required(self):
        obs = self.build()
        obs["diagnostics"] = [{"code": "safe", "message": "https://example.com?credential=value"}]
        with self.assertRaises(ContractError): validate_observation(obs)
        obs = self.build(); obs["readback"].pop("authenticated")
        with self.assertRaises(ContractError): validate_observation(obs)
