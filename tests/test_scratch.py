"""Tests for descriptor-relative scratch utilities and bounded JSON validation."""
from __future__ import annotations

import math
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.scratch import ConfinedWriter, canonical, physical_directory, validate_safe_json, verify_public_tree_modes


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

    def test_confined_writer_modes_independent_of_umask(self):
        for test_mask in (0o022, 0o077):
            with self.subTest(umask=oct(test_mask)):
                orig_mask = os.umask(test_mask)
                try:
                    with tempfile.TemporaryDirectory() as tmp:
                        tmp_path = Path(tmp).resolve()
                        with ConfinedWriter(tmp_path, file_mode=0o644, dir_mode=0o755) as writer:
                            writer.write("a/b/c/file.txt", b"data")
                        file_st = (tmp_path / "a/b/c/file.txt").stat()
                        dir_st = (tmp_path / "a/b/c").stat()
                        self.assertEqual(stat.S_IMODE(file_st.st_mode), 0o644)
                        self.assertEqual(stat.S_IMODE(dir_st.st_mode), 0o755)
                        self.assertEqual(stat.S_IMODE((tmp_path / "a/b").stat().st_mode), 0o755)
                        self.assertEqual(stat.S_IMODE((tmp_path / "a").stat().st_mode), 0o755)
                finally:
                    os.umask(orig_mask)

    def test_default_writer_keeps_ambient_umask_contract(self):
        for mask in (0o022,0o077):
            previous=os.umask(mask)
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    root=Path(tmp).resolve()
                    with ConfinedWriter(root) as writer:
                        writer.write("private/file.txt",b"fixture")
                    self.assertEqual(stat.S_IMODE((root/"private").stat().st_mode),0o755 & ~mask)
                    self.assertEqual(stat.S_IMODE((root/"private/file.txt").stat().st_mode),0o644 & ~mask)
            finally:
                os.umask(previous)

    def test_confined_writer_custom_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            with ConfinedWriter(tmp_path, file_mode=0o600, dir_mode=0o700) as writer:
                writer.write("sub/secret.txt", b"secret data")
            self.assertEqual(stat.S_IMODE((tmp_path / "sub/secret.txt").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((tmp_path / "sub").stat().st_mode), 0o700)


class VerifyPublicTreeModesTests(unittest.TestCase):
    def test_verify_public_tree_modes_passes_for_standard_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "public_root"
            root.mkdir()
            root.chmod(0o755)
            (root / "dir1").mkdir()
            (root / "dir1").chmod(0o755)
            (root / "dir1/file.txt").write_bytes(b"content")
            (root / "dir1/file.txt").chmod(0o644)

            res = verify_public_tree_modes(root)
            self.assertEqual(res["status"], "pass")
            self.assertEqual(res["counts"]["file_mode"], 0)
            self.assertEqual(res["counts"]["directory_mode"], 0)
            self.assertEqual(res["counts"]["dir_mode"], 0)
            self.assertEqual(res["counts"]["symlink"], 0)
            self.assertEqual(res["counts"]["special"], 0)
            self.assertEqual(res["counts"]["total_files"], 1)
            self.assertEqual(res["counts"]["total_directories"], 2)
            self.assertEqual(res["mismatch_samples"]["file_mode"], [])
            self.assertEqual(res["mismatch_samples"]["directory_mode"], [])

    def test_verify_public_tree_modes_detects_mode_mismatches_and_bounds_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "bad_root"
            root.mkdir()
            root.chmod(0o700)  # Bad dir mode
            sub = root / "sub"
            sub.mkdir()
            sub.chmod(0o750)  # Bad dir mode

            # Create 15 files with bad mode 0o600 to test sample bounding to 10
            for i in range(15):
                f = sub / f"file_{i}.txt"
                f.write_bytes(b"test")
                f.chmod(0o600)

            res = verify_public_tree_modes(root)
            self.assertEqual(res["status"], "fail")
            self.assertEqual(res["counts"]["file_mode"], 15)
            self.assertEqual(res["counts"]["directory_mode"], 2)
            self.assertEqual(res["counts"]["dir_mode"], 2)
            self.assertEqual(len(res["mismatch_samples"]["file_mode"]), 10)
            self.assertEqual(len(res["mismatch_samples"]["directory_mode"]), 2)
            self.assertEqual(res["mismatch_samples"]["file_mode"][0]["expected_mode"], 0o644)
            self.assertEqual(res["mismatch_samples"]["file_mode"][0]["actual_mode"], 0o600)

    def test_verify_public_tree_modes_refuses_symlink_root_and_in_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_dir = Path(tmp).resolve() / "real"
            real_dir.mkdir()
            real_dir.chmod(0o755)
            link_dir = Path(tmp).resolve() / "link"
            link_dir.symlink_to(real_dir)

            # Symlink root returns fail by default
            res = verify_public_tree_modes(link_dir)
            self.assertEqual(res["status"], "fail")
            self.assertEqual(res["counts"]["symlink"], 1)

            # raise_on_error raises ContractError
            with self.assertRaises(ContractError) as ctx:
                verify_public_tree_modes(link_dir, raise_on_error=True)
            self.assertEqual(ctx.exception.code, "SYMLINK_REJECTED")

            # Symlink inside tree
            target_file = real_dir / "target.txt"
            target_file.write_bytes(b"data")
            target_file.chmod(0o644)
            sym = real_dir / "link.txt"
            sym.symlink_to(target_file)

            res2 = verify_public_tree_modes(real_dir)
            self.assertEqual(res2["status"], "fail")
            self.assertGreaterEqual(res2["counts"]["symlink"], 1)

            with self.assertRaises(ContractError) as ctx2:
                verify_public_tree_modes(real_dir, raise_on_error=True)
            self.assertEqual(ctx2.exception.code, "SYMLINK_REJECTED")

    def test_verify_public_tree_modes_refuses_special_objects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "special_root"
            root.mkdir()
            root.chmod(0o755)
            fifo = root / "test_fifo"
            try:
                os.mkfifo(str(fifo))
            except (AttributeError, OSError):
                self.skipTest("os.mkfifo not supported on this platform")

            res = verify_public_tree_modes(root)
            self.assertEqual(res["status"], "fail")
            self.assertEqual(res["counts"]["special"], 1)
            self.assertEqual(res["mismatch_samples"]["special"][0]["type"], "fifo")

            with self.assertRaises(ContractError) as ctx:
                verify_public_tree_modes(root, raise_on_error=True)
            self.assertEqual(ctx.exception.code, "INVALID_FILE")


if __name__ == "__main__":
    unittest.main()
