"""Closed first-failure tokens, privacy and descriptor-only artifact observations."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9.release_core import digest
from rs9.smoke_stream_tokens import (
    collect_failure_diagnostics, evidence_inventory, stream_tokens,
    validate_inventory, validate_stream_tokens,
)


class StreamTests(unittest.TestCase):
    def test_closed_tokens_and_original_identity(self):
        raw = b"EACCES: permission denied, mkdir '/tmp/guest-work'\n"
        doc = stream_tokens(raw, complete=True)
        self.assertEqual(doc["tokens"], ["node-errno-eacces", "node-syscall-mkdir"])
        self.assertEqual(doc["sha256"], digest(raw))
        self.assertEqual(doc["bytes"], len(raw))
        self.assertNotIn("guest-work", json.dumps(doc))
        self.assertEqual(validate_stream_tokens(doc, sha256=digest(raw), byte_count=len(raw), complete=True), doc)

    def test_withhold_empty_garbled_unterminated_private_and_incomplete(self):
        cases = [(b"", True, "empty"), (b"TypeError: unterminated", True, "unterminated"),
                 (b"TypeError: \xff\n", True, "invalid-utf8"),
                 (b"TypeError: nul\0\n", True, "control-bytes"),
                 (b"TypeError: /" + b"home/" + b"private-user/data\n", True, "private"),
                 (b"TypeError: /" + b"home/" + b"runner/work/source\n", True, "private"),
                 (b"TypeError: password=redacted\n", True, "private"),
                 (("TypeError: " + "ghp_" + "x" * 36 + "\n").encode(), True, "private"),
                 (b"TypeError: ordinary\n", False, "incomplete"),
                 (b"x" * 65537, True, "oversize")]
        for raw, complete, reason in cases:
            with self.subTest(reason=reason):
                doc = stream_tokens(raw, complete=complete)
                self.assertEqual(doc["tokens"], [])
                self.assertEqual(doc["withheld_reason"], reason)
                self.assertNotIn("private-user", json.dumps(doc))
                projected = validate_stream_tokens(doc, sha256=digest(raw), byte_count=len(raw), complete=complete)
                self.assertEqual(projected, doc)
                if reason in {"incomplete", "oversize"}:
                    self.assertIsNone(doc["line_count"])
                    self.assertIsNone(doc["utf8_valid"])

    def test_token_overflow_is_explicit_and_projection_preserves_it(self):
        raw = (b"TypeError: ordinary\nReferenceError: ordinary\nSyntaxError: ordinary\n"
               b"candidate executable is not executable\n"
               b"maintained core fixture project name changed\n"
               b"maintained core fixture brand changed\n"
               b"ENOENT: no such file, open '/tmp/fixture'\n"
               b"EACCES: permission denied, mkdir '/tmp/fixture'\n")
        doc = stream_tokens(raw, complete=True)
        self.assertEqual(len(doc["tokens"]), 8)
        self.assertEqual(doc["tokens_omitted"], 2)
        self.assertEqual(validate_stream_tokens(doc, sha256=digest(raw),
            byte_count=len(raw), complete=True), doc)
        for count in (-1, True, "private", 100, 1):
            hostile = {**doc, "tokens_omitted": count}
            if count == 1 and type(count) is int:
                hostile["tokens"] = ["node-type-error"]
            projected = validate_stream_tokens(hostile, sha256=digest(raw),
                byte_count=len(raw), complete=True)
            self.assertEqual(projected["withheld_reason"], "invalid-observation")
            self.assertEqual(projected["tokens"], [])
            self.assertEqual(projected["tokens_omitted"], 0)
        duplicate = {**doc, "tokens": ["node-type-error"] * 8}
        projected = validate_stream_tokens(duplicate, sha256=digest(raw),
            byte_count=len(raw), complete=True)
        self.assertEqual(projected["withheld_reason"], "invalid-observation")
        self.assertEqual(validate_stream_tokens(projected, sha256=digest(raw),
            byte_count=len(raw), complete=True), projected)

    def test_fixed_release_message_and_untrusted_prose(self):
        doc = stream_tokens(b"candidate executable is not executable\n", complete=True)
        self.assertEqual(doc["tokens"], ["release-executable-not-executable"])
        self.assertEqual(stream_tokens(b"please report node-errno-eacces\n", complete=True)["tokens"], [])

    def test_projection_rejects_hash_size_stage_and_unknown_token(self):
        raw = b"TypeError: ordinary\n"
        doc = stream_tokens(raw, complete=True)
        for key, value in (("sha256", "f" * 64), ("bytes", len(raw) - 1),
                           ("stage", "replay"), ("tokens", ["node-type-error", "/home/private"]),
                           ("tokens", {"private": "response"}), ("withheld_reason", [])):
            with self.subTest(key=key):
                projected = validate_stream_tokens({**doc, key: value}, sha256=digest(raw),
                    byte_count=len(raw), complete=True)
                self.assertEqual(projected["tokens"], [])
                self.assertEqual(projected["withheld_reason"], "invalid-observation")
                self.assertEqual(validate_stream_tokens(projected, sha256=digest(raw),
                    byte_count=len(raw), complete=True), projected)

    def test_each_diagnostic_exception_is_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("rs9.smoke_stream_tokens.stream_tokens", side_effect=OSError):
                doc = collect_failure_diagnostics(b"bad\n", {"stream_capture_complete": True}, Path(tmp), "linux-x64", "C")
            self.assertIn("evidence_inventory", doc)
            with patch("rs9.smoke_stream_tokens.evidence_inventory", side_effect=OSError):
                doc = collect_failure_diagnostics(b"bad\n", {"stream_capture_complete": True}, Path(tmp), "linux-x64", "C")
            self.assertIn("stderr_diagnostic", doc)


class InventoryTests(unittest.TestCase):
    def test_no_follow_no_private_names_or_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            private = root / "private-name"
            private.write_text("private-content")
            (root / "linux-x64-C.stdout.log").write_bytes(b"secret content")
            (root / "linux-x64-C.run.json").symlink_to(private)
            doc = evidence_inventory(root, "linux-x64", "C")
            self.assertEqual(doc["entries_observed"], 3)
            self.assertEqual(doc["unlisted"], 1)
            run = next(x for x in doc["artifacts"] if x["kind"] == "run.json")
            self.assertTrue(run["symlink"])
            self.assertFalse(run["regular"])
            self.assertNotIn("private-name", json.dumps(doc))
            self.assertNotIn("secret content", json.dumps(doc))
            self.assertEqual(validate_inventory(doc), doc)

    def test_bound_entries_and_symlink_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            directory = root / "evidence"
            directory.mkdir()
            for i in range(40):
                (directory / str(i)).touch()
            doc = evidence_inventory(directory, "linux-arm64", "B")
            self.assertEqual(doc["entries_observed"], 32)
            self.assertEqual(doc["status"], "limit-exceeded")
            self.assertEqual(validate_inventory(doc), doc)
            link = root / "link"
            link.symlink_to(directory)
            self.assertEqual(evidence_inventory(link, "linux-arm64", "B")["status"], "unavailable")

    def test_hostile_inventory_values_withheld(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc = evidence_inventory(Path(tmp), "linux-x64", "C")
        for key, value in (("status", []), ("artifacts", [{"kind": "private-name"}]),
                           ("entries_observed", True), ("unlisted", 33)):
            result = validate_inventory({**doc, key: value})
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(validate_inventory(result), result)
