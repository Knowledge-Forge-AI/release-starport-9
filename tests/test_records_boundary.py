"""Tests for record boundary validation, diagnostic enrichment, and failure iteration."""
import copy
import json
from pathlib import Path
import unittest

from rs9.errors import ContractError
from rs9.records import (
    Record,
    record_boundary_failures,
    record_sha256,
    sanitized,
    snapshot,
    validate_bounded_int,
    validate_rfc3339_utc,
    validate_sanitized_string,
    validate_sha256,
)

EVIDENCE_DIR = Path(__file__).parent / "fixtures/run10/rpm"


class TestRecordsBoundary(unittest.TestCase):
    def test_minimal_safe_record_passes(self):
        record = {"status": "candidate", "details": None, "count": 0, "active": True}
        self.assertEqual(snapshot(record), record)

    def test_empty_string_rejected_with_field_path_and_rule(self):
        data = {"findings": [{"check": "test", "message": ""}]}
        with self.assertRaises(ContractError) as caught:
            sanitized(data)
        self.assertEqual(caught.exception.code, "INVALID_STRING")
        self.assertEqual(getattr(caught.exception, "field_path", None), "$.findings[0].message")
        self.assertEqual(getattr(caught.exception, "rule", None), "INVALID_STRING")

    def test_control_character_rejected_with_field_path_and_rule(self):
        data = {"nested": {"lines": ["safe", "hello\nworld"]}}
        with self.assertRaises(ContractError) as caught:
            sanitized(data)
        self.assertEqual(caught.exception.code, "INVALID_CONTENT")
        self.assertEqual(getattr(caught.exception, "field_path", None), "$.nested.lines[1]")
        self.assertEqual(getattr(caught.exception, "rule", None), "INVALID_CONTENT")

    def test_private_path_rejected_with_field_path_and_rule(self):
        data = {"config": {"log_path": "/" + "home/developer/app.log"}}
        with self.assertRaises(ContractError) as caught:
            sanitized(data)
        self.assertEqual(caught.exception.code, "PRIVATE_PATH")
        self.assertEqual(getattr(caught.exception, "field_path", None), "$.config.log_path")
        self.assertEqual(getattr(caught.exception, "rule", None), "PRIVATE_PATH")

    def test_unsafe_url_rejected_with_field_path_and_rule(self):
        data = {"meta": {"repo": "https://user:pass@github.com/org/repo"}}
        with self.assertRaises(ContractError) as caught:
            sanitized(data)
        self.assertEqual(caught.exception.code, "UNSAFE_URL")
        self.assertEqual(getattr(caught.exception, "field_path", None), "$.meta.repo")
        self.assertEqual(getattr(caught.exception, "rule", None), "UNSAFE_URL")

    def test_record_type_rejected_with_field_path_and_rule(self):
        data = {"values": [1, 2, 3.14]}
        with self.assertRaises(ContractError) as caught:
            sanitized(data)
        self.assertEqual(caught.exception.code, "RECORD_TYPE")
        self.assertEqual(getattr(caught.exception, "field_path", None), "$.values[2]")
        self.assertEqual(getattr(caught.exception, "rule", None), "RECORD_TYPE")

    def test_dict_key_failure_has_field_path(self):
        data = {"normal": {"": "bad key"}}
        with self.assertRaises(ContractError) as caught:
            sanitized(data)
        self.assertEqual(caught.exception.code, "INVALID_STRING")
        self.assertEqual(getattr(caught.exception, "field_path", None), "$.normal.<key>")
        self.assertEqual(getattr(caught.exception, "rule", None), "INVALID_STRING")

    def test_record_depth_limit_has_field_path(self):
        cur = "deep"
        for _ in range(14):
            cur = {"nest": cur}
        with self.assertRaises(ContractError) as caught:
            sanitized(cur)
        self.assertEqual(caught.exception.code, "RECORD_LIMIT")
        self.assertTrue(getattr(caught.exception, "field_path", "").startswith("$.nest"))
        self.assertEqual(getattr(caught.exception, "rule", None), "RECORD_LIMIT")

    def test_record_boundary_failures_iterates_all_errors(self):
        bad_data = {
            "a": "",
            "b": "/home/user",
            "c": "safe",
            "d": ["item", "bad\x01ctrl", 3.1415],
            "e": None,
        }
        failures = record_boundary_failures(bad_data)
        self.assertEqual(len(failures), 4)
        field_paths = [f["field_path"] for f in failures]
        rules = [f["rule"] for f in failures]
        self.assertEqual(field_paths, ["$.a", "$.b", "$.d[1]", "$.d[2]"])
        self.assertEqual(rules, ["INVALID_STRING", "PRIVATE_PATH", "INVALID_CONTENT", "RECORD_TYPE"])

    def test_retained_nebular_raw_lint_boundary_replay(self):
        """Reproduce exact 4 empty-message boundary failures from retained raw lint."""
        for system in ("x86_64-linux", "aarch64-linux"):
            raw_path = (
                EVIDENCE_DIR
                / system / Path("raw-lint.json")
            )
            raw = json.loads(raw_path.read_bytes())
            wrapped = {"evidence": {"rpmlint": raw}}

            # Unchanged sanitized fails with INVALID_STRING at first empty message
            with self.assertRaises(ContractError) as caught:
                sanitized(wrapped)
            self.assertEqual(caught.exception.code, "INVALID_STRING")
            self.assertEqual(
                getattr(caught.exception, "field_path", None),
                "$.evidence.rpmlint.findings[14].message",
            )
            self.assertEqual(getattr(caught.exception, "rule", None), "INVALID_STRING")

            # record_boundary_failures finds exactly the 4 empty message fields recorded in replay
            failures = record_boundary_failures(wrapped)
            self.assertEqual(len(failures), 4)
            expected_fields = [
                "$.evidence.rpmlint.findings[14].message",
                "$.evidence.rpmlint.findings[15].message",
                "$.evidence.rpmlint.groups[9].samples[0].message",
                "$.evidence.rpmlint.groups[10].samples[0].message",
            ]
            self.assertEqual([f["field_path"] for f in failures], expected_fields)
            for f in failures:
                self.assertEqual(f["rule"], "INVALID_STRING")

            # Counterfactual: setting only those empty messages to None passes without changing raw
            counterfactual = copy.deepcopy(wrapped)

            def nullify_empty_messages(obj):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if k == "message" and v == "":
                            obj[k] = None
                        else:
                            nullify_empty_messages(v)
                elif isinstance(obj, list):
                    for v in obj:
                        nullify_empty_messages(v)

            nullify_empty_messages(counterfactual)
            # Sanitized passes on counterfactual
            sanitized(counterfactual)
            self.assertEqual(record_boundary_failures(counterfactual), [])

    def test_deep_copy_and_immutability(self):
        orig = {"list": [{"name": "alpha"}]}
        snapped = snapshot(orig)
        snapped["list"][0]["name"] = "beta"
        self.assertEqual(orig["list"][0]["name"], "alpha")
