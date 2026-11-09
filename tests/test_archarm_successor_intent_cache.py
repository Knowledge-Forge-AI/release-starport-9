"""In-memory ArchARM client/parser composition; no native SDK or scanner runs."""
import base64
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from rs9 import archarm_sdk, client_inventory as inventory, hosted_deb
from rs9._archarm_support import origin, successor_20261109
from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from tests.test_client_inventory import _make_framed_payload


CACHE = "usr/share/applications/intent.cache"
SUCCESSOR = successor_20261109.INPUTS["package_pins_sha256"]


def entry(path=CACHE, kind="file", *, sha="a" * 64, mode=0o644):
    row = {"kind": kind, "mode": mode,
           "path": base64.b64encode(path.encode()).decode()}
    if kind == "file":
        row.update(sha256=sha, size=10)
    elif kind == "symlink":
        row["target"] = base64.b64encode(b"other-cache").decode()
    elif kind in ("char", "block"):
        row["rdev"] = 123
    return row


class SuccessorIntentCacheTests(unittest.TestCase):
    def capture(self, rows, *, qualified=True, digest=SUCCESSOR, stage="post-remove",
                exit_code=0, stderr=b""):
        client = archarm_sdk.ArchArmClient.__new__(archarm_sdk.ArchArmClient)
        state = SimpleNamespace(pins_qualified=qualified, digests={} if digest is None else
                                {"packagePinsSha256": digest})
        client._running = Mock(return_value=state)
        client._exec_with_capture = Mock(return_value=CommandReceipt(
            inventory.scanner_argv(family="pacman"), exit_code,
            _make_framed_payload(rows), stderr))
        result = client.inventory(stage)
        client._running.assert_called_once_with()
        client._exec_with_capture.assert_called_once_with(
            inventory.scanner_argv(family="pacman"), output_limit=inventory.MAX_STDOUT_BYTES)
        self.assertEqual(client.last_inventory_stage, stage)
        self.assertEqual(client.last_diagnostics["counters"]["scanned_entries"], len(rows))
        return result

    def test_qualified_successor_regular_cache_is_excluded_by_actual_adapter_parser(self):
        result = self.capture([entry(), entry("usr/bin/retained", mode=0o755)])
        self.assertEqual(result, {"usr/bin/retained": "a" * 64 + ":0755"})

    def test_both_literal_qualification_and_exact_successor_digest_are_required(self):
        cases = [(False, SUCCESSOR), (1, SUCCESSOR), ("true", SUCCESSOR),
                 (None, SUCCESSOR), (True, origin.ORIGIN_FILES["PACKAGE-PINS.json"]["sha256"]),
                 (True, "0" * 64), (True, None)]
        for qualified, digest in cases:
            with self.subTest(qualified=qualified, digest=digest):
                self.assertIn(CACHE, self.capture([entry()], qualified=qualified, digest=digest))

    def test_same_path_nonregular_entries_remain_inventoried_and_unclean(self):
        for kind in ("dir", "symlink", "fifo", "socket", "char", "block"):
            with self.subTest(kind=kind):
                result = self.capture([entry(kind=kind)])
                self.assertIn(CACHE, result)
                self.assertFalse(inventory.compare_inventories({}, result)["clean"])

    def test_neighbors_children_and_spelling_variants_remain_inventoried(self):
        for path in (CACHE + ".bak", CACHE + "/child", CACHE.upper(),
                     "usr/share/applications/other.cache", "usr/share/applications2/intent.cache",
                     "usr/share/applications\\intent.cache"):
            with self.subTest(path=path):
                self.assertIn(path, self.capture([entry(path)]))

    def test_generated_regular_cache_is_symmetric_but_unrelated_changes_fail(self):
        before = self.capture([entry("usr/bin/retained")], stage="pre-install")
        after = self.capture([entry("usr/bin/retained"), entry()])
        self.assertTrue(inventory.compare_inventories(before, after)["clean"])
        self.assertTrue(inventory.compare_inventories(after, before)["clean"])
        changed = self.capture([entry("usr/bin/retained", sha="b" * 64), entry()])
        self.assertEqual(inventory.compare_inventories(before, changed)["modified"],
                         ["usr/bin/retained"])
        leftover = self.capture([entry("usr/bin/retained"), entry(), entry("usr/bin/leftover")])
        self.assertEqual(inventory.compare_inventories(before, leftover)["added"],
                         ["usr/bin/leftover"])

    def test_global_pacman_and_other_family_policies_are_unchanged(self):
        for family in ("apt", "dnf", "pacman"):
            with self.subTest(family=family):
                self.assertFalse(hosted_deb.inventory_excluded(family, CACHE))
                self.assertIn(CACHE, hosted_deb.parse_inventory(_make_framed_payload([entry()]), family))

    def test_excluded_regular_file_still_must_pass_protocol_validation(self):
        for row in (entry(sha="invalid"), {**entry(), "unexpected": "field"},
                    {**entry(), "mode": -1}, {**entry(), "size": -1}):
            with self.subTest(row=row), self.assertRaises(ContractError):
                self.capture([row])

    def test_scanner_error_is_not_swallowed_by_file_exclusion(self):
        for code, stderr in ((1, b""), (0, b"untrusted-error")):
            with self.subTest(code=code), self.assertRaises(ContractError) as error:
                self.capture([entry()], exit_code=code, stderr=stderr)
            self.assertEqual(error.exception.code, "INVENTORY_FAILED")


if __name__ == "__main__":
    unittest.main()
