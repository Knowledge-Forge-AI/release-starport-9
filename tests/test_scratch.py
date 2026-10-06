"""Tests for descriptor-relative scratch utilities and bounded JSON validation."""
from __future__ import annotations

import math
import json
from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.scratch import ConfinedWriter, canonical, physical_directory, validate_safe_json


class FakeReleaseCapture:
    """Mock un-serializable release capture object to test privacy-safe rejection."""
    def __init__(self, private_token="secret_token_12345"):
        self.private_token = private_token

    def __repr__(self):
        return f"<FakeReleaseCapture secret={self.private_token}>"


class ScratchValidationTests(unittest.TestCase):
    def test_canonical_produces_deterministic_bytes_with_newline(self):
        data = {"b": 2, "a": 1}
        output = canonical(data)
        self.assertIsInstance(output, bytes)
        self.assertTrue(output.endswith(b"\n"))
        self.assertEqual(output, b'{\n  "a": 1,\n  "b": 2\n}\n')

    def test_canonical_preserves_canonical_exception_behavior_by_default(self):
        """Unvalidated canonical raises TypeError from json.dumps, preserving caller contract."""
        with self.assertRaises(TypeError):
            canonical({"obj": object()})

        with self.assertRaises(TypeError):
            canonical(FakeReleaseCapture())

    def test_canonical_with_validation_raises_contract_error(self):
        with self.assertRaises(ContractError) as ctx:
            canonical({"obj": object()}, validate=True)
        self.assertEqual(ctx.exception.code, "INVALID_JSON")

    def test_validate_safe_json_allows_valid_types(self):
        payload = {
            "str": "hello",
            "int": 42,
            "float": 3.14,
            "bool": True,
            "none": None,
            "list": [1, "two", 3.0, [False, None]],
            "dict": {"nested": "value", "empty": {}},
        }
        result = validate_safe_json(payload)
        self.assertIs(result, payload)

    def test_validate_safe_json_reports_logical_path_and_safe_type(self):
        bad_val = FakeReleaseCapture("super_secret_key")
        data = {
            "system": "x86_64-linux",
            "prepared": {
                "source": "/path/to/source",
                "capture": bad_val,
            },
        }

        with self.assertRaises(ContractError) as ctx:
            validate_safe_json(
                data,
                lane="wheels",
                product="theme-forge-nebular-fusion",
                field="client_config",
            )

        err = ctx.exception
        self.assertEqual(err.code, "INVALID_JSON")
        self.assertIn("FakeReleaseCapture", str(err))
        self.assertIn("client_config.prepared.capture", str(err))

        # Privacy guarantee: private tokens or arbitrary repr must NOT appear
        self.assertNotIn("super_secret_key", str(err))
        self.assertNotIn("secret=", str(err))

        # Check safe details reporting
        self.assertEqual(err.details.get("origin"), "client_config.prepared.capture")
        self.assertEqual(err.details.get("exception_type"), "FakeReleaseCapture")
        self.assertEqual(err.details.get("product"), "theme-forge-nebular-fusion")
        self.assertEqual(err.details.get("substage"), "wheels")
        self.assertEqual(err.details.get("reason"), "non-json-value")

    def test_validate_safe_json_rejects_path_objects(self):
        data = {"path": Path("/some/posix/path")}
        with self.assertRaises(ContractError) as ctx:
            validate_safe_json(data)
        self.assertEqual(ctx.exception.code, "INVALID_JSON")
        self.assertIn("PosixPath", ctx.exception.details.get("exception_type", ""))

    def test_validate_safe_json_rejects_non_string_dict_keys(self):
        data = {123: "value"}
        with self.assertRaises(ContractError) as ctx:
            validate_safe_json(data)
        self.assertEqual(ctx.exception.code, "INVALID_JSON")
        self.assertEqual(ctx.exception.details.get("reason"), "non-string-dict-key")

    def test_validate_safe_json_rejects_non_finite_floats(self):
        for bad_float in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(val=bad_float), self.assertRaises(ContractError) as ctx:
                validate_safe_json({"number": bad_float})
            self.assertEqual(ctx.exception.code, "INVALID_JSON")
            self.assertEqual(ctx.exception.details.get("reason"), "non-finite-float")

    def test_validate_safe_json_rejects_circular_references(self):
        cycle = {}
        cycle["self"] = cycle
        with self.assertRaises(ContractError) as ctx:
            validate_safe_json(cycle)
        self.assertEqual(ctx.exception.code, "INVALID_JSON")
        self.assertEqual(ctx.exception.details.get("reason"), "circular-reference")

    def test_validate_safe_json_rejects_excessive_depth(self):
        nested = "bottom"
        for _ in range(70):
            nested = [nested]
        with self.assertRaises(ContractError) as ctx:
            validate_safe_json(nested, max_depth=64)
        self.assertEqual(ctx.exception.code, "INVALID_JSON")
        self.assertEqual(ctx.exception.details.get("reason"), "max-depth-exceeded")

    def test_unsafe_keys_and_custom_type_names_never_enter_messages(self):
        secret_key = "/private/fixture/token-value"
        odd = type("/private/fixture/type", (), {})()
        with self.assertRaises(ContractError) as caught:
            validate_safe_json({secret_key: odd}, lane="wheels", product="theme-forge-nebular-fusion")
        self.assertNotIn(secret_key, str(caught.exception))
        self.assertNotIn("/private/", json.dumps(caught.exception.details))
        self.assertEqual(caught.exception.details["exception_type"], "unknown_type")
        self.assertIn("key-sha256-", caught.exception.details["origin"])

    def test_node_count_and_path_length_are_bounded(self):
        with self.assertRaises(ContractError) as caught:
            validate_safe_json([None] * 20, max_nodes=10)
        self.assertEqual(caught.exception.details["reason"], "max-nodes-exceeded")
        with self.assertRaises(ContractError) as caught:
            validate_safe_json({"x" * 10000: object()})
        self.assertLess(len(str(caught.exception)), 256)


class PhysicalDirectoryAndWriterTests(unittest.TestCase):
    def test_physical_directory_validates_real_dir_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            self.assertEqual(physical_directory(tmp_path), tmp_path)

            link = tmp_path / "link_dir"
            link.symlink_to(tmp_path)
            with self.assertRaises(ContractError) as ctx:
                physical_directory(link)
            self.assertEqual(ctx.exception.code, "SYMLINK_REJECTED")

    def test_confined_writer_writes_exclusively(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            with ConfinedWriter(tmp_path) as writer:
                writer.write("nested/sub/file.txt", b"hello world")
            self.assertEqual((tmp_path / "nested/sub/file.txt").read_bytes(), b"hello world")


if __name__ == "__main__":
    unittest.main()
