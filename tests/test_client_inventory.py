"""Hermetic unit tests and adverse test suite for client_inventory module."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import rs9.client_inventory as ci
from rs9.errors import ContractError


def _make_framed_payload(
    entries: list[dict],
    *,
    schema: str = ci.FRAME_SCHEMA,
    version: int = ci.FRAME_VERSION,
    entry_count: int | None = None,
    total_hashed_bytes: int | None = None,
    sort_entries: bool = True,
    extra_top_fields: dict | None = None,
) -> bytes:
    if sort_entries:
        entries = sorted(entries, key=lambda e: base64.b64decode(e["path"]))
    if entry_count is None:
        entry_count = len(entries)
    if total_hashed_bytes is None:
        total_hashed_bytes = sum(e.get("size", 0) for e in entries if e.get("kind") == "file")

    def encoded_length(value):
        try:
            return len(base64.b64decode(value))
        except Exception:
            return 0
    diagnostics = {"counters": {
        "dir_count": sum(e.get("kind") in ("dir", "mount") for e in entries),
        "file_count": sum(e.get("kind") == "file" for e in entries),
        "symlink_count": sum(e.get("kind") == "symlink" for e in entries),
        "special_count": sum(e.get("kind") in ("fifo", "socket", "char", "block") for e in entries),
        "hardlink_count": 0, "entries": len(entries), "total_hashed_bytes": total_hashed_bytes,
        "scanned_entries": len(entries), "excluded_files": 0},
        "max": {"depth": 0,
                "file_bytes": max((e.get("size", 0) for e in entries if type(e.get("size", 0)) is int), default=0),
                "path_bytes": max((encoded_length(e["path"]) for e in entries), default=0),
                "symlink_bytes": max((encoded_length(e["target"]) for e in entries if e.get("kind") == "symlink"), default=0),
                "directory_entries": 0}}
    payload: dict = {"diagnostics": diagnostics,
        "entries": entries,
        "entry_count": entry_count,
        "schema": schema,
        "total_hashed_bytes": total_hashed_bytes,
        "version": version,
    }
    if extra_top_fields:
        payload.update(extra_top_fields)

    json_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return ci.frame_payload(payload)


class ClientInventoryRoundTripTests(unittest.TestCase):
    """Test real scanner subprocess execution and real framed parser round-trip."""

    def test_real_scanner_subprocess_and_framed_parser_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()

            # Create directories
            (root / "usr" / "bin").mkdir(parents=True)
            (root / "etc").mkdir(parents=True)

            # Create regular files
            f1 = root / "usr" / "bin" / "app"
            f1.write_bytes(b"binary payload content\n")
            f2 = root / "etc" / "config.conf"
            f2.write_bytes(b"setting = true\n")

            # Create symlink
            link = root / "usr" / "bin" / "app_link"
            os.symlink("app", link)

            # Run scanner subprocess
            argv = ci.scanner_argv(root=str(root))
            proc = subprocess.run(argv, capture_output=True, check=False)
            self.assertEqual(proc.returncode, 0, f"Scanner failed: {proc.stderr.decode('utf-8', errors='replace')}")

            # Parse framed output
            inv = ci.parse_inventory(proc.stdout)

            # Assert inventory entries
            self.assertEqual(inv["usr"], "dir")
            self.assertEqual(inv["usr/bin"], "dir")
            self.assertEqual(inv["etc"], "dir")
            self.assertEqual(inv["usr/bin/app"], hashlib.sha256(b"binary payload content\n").hexdigest())
            self.assertEqual(inv["etc/config.conf"], hashlib.sha256(b"setting = true\n").hexdigest())
            self.assertEqual(inv["usr/bin/app_link"], "symlink:app")

            # run_and_parse integration
            direct_inv = ci.run_and_parse(root=str(root))
            self.assertEqual(direct_inv, inv)

    def test_deterministic_bytes_ordering(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            # Create files in arbitrary order
            for name in ["z_file", "a_file", "m_file", "1_file", "b_dir/sub"]:
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"content")

            argv = ci.scanner_argv(root=str(root))
            run1 = subprocess.run(argv, capture_output=True, check=True).stdout
            run2 = subprocess.run(argv, capture_output=True, check=True).stdout

            # Exactly deterministic output bytes
            self.assertEqual(run1, run2)


class ClientInventorySpecialPathsTests(unittest.TestCase):
    """Test paths with spaces, newlines, backslashes, arrows, and invalid UTF-8."""

    def test_paths_with_spaces_newlines_backslashes_and_arrows(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()

            # Space in filename
            f_space = root / "file with spaces.txt"
            f_space.write_bytes(b"space content")

            # Newline in filename
            f_nl = root / "file\nwith\nnewlines.txt"
            f_nl.write_bytes(b"newline content")

            # Backslash in filename (no backslash folding!)
            f_bs = root / "file\\with\\backslash.txt"
            f_bs.write_bytes(b"backslash content")

            # Arrow in filename
            f_arrow = root / "file -> arrow.txt"
            f_arrow.write_bytes(b"arrow content")

            # Symlink with arrow in name and target
            symlink = root / "symlink -> with -> arrow"
            os.symlink("file -> arrow.txt", symlink)

            inv = ci.run_and_parse(root=str(root))

            self.assertIn("file with spaces.txt", inv)
            self.assertEqual(inv["file with spaces.txt"], hashlib.sha256(b"space content").hexdigest())

            self.assertIn("file\nwith\nnewlines.txt", inv)
            self.assertEqual(inv["file\nwith\nnewlines.txt"], hashlib.sha256(b"newline content").hexdigest())

            self.assertIn("file\\with\\backslash.txt", inv)
            self.assertEqual(inv["file\\with\\backslash.txt"], hashlib.sha256(b"backslash content").hexdigest())

            self.assertIn("file -> arrow.txt", inv)
            self.assertEqual(inv["file -> arrow.txt"], hashlib.sha256(b"arrow content").hexdigest())

            self.assertIn("symlink -> with -> arrow", inv)
            self.assertEqual(inv["symlink -> with -> arrow"], "symlink:file -> arrow.txt")

    def test_invalid_utf8_lossless_surrogateescape_handling(self):
        raw_bad_path = b"dir/file_\xff\xfe_invalid_utf8.bin"
        raw_bad_target = b"target_\x80\x81.bin"

        entries = [
            {
                "kind": "file",
                "mode": 0o644,
                "path": base64.b64encode(raw_bad_path).decode("ascii"),
                "sha256": "0" * 64,
                "size": 10,
            },
            {
                "kind": "symlink",
                "mode": 0o777,
                "path": base64.b64encode(b"symlink_bad").decode("ascii"),
                "target": base64.b64encode(raw_bad_target).decode("ascii"),
            },
        ]
        framed = _make_framed_payload(entries)
        inv = ci.parse_inventory(framed)

        # Keys are decoded with surrogateescape
        expected_key = raw_bad_path.decode("utf-8", errors="surrogateescape")
        self.assertIn(expected_key, inv)
        # Lossless re-encoding reproduces the exact raw bytes!
        self.assertEqual(expected_key.encode("utf-8", errors="surrogateescape"), raw_bad_path)

        expected_target_str = raw_bad_target.decode("utf-8", errors="surrogateescape")
        self.assertEqual(inv["symlink_bad"], f"symlink:{expected_target_str}")
        self.assertEqual(expected_target_str.encode("utf-8", errors="surrogateescape"), raw_bad_target)


class ClientInventoryHardlinksAndSpecialTests(unittest.TestCase):
    """Test hardlinks, special files (FIFO, sockets), and mount entries."""

    def test_hardlinks_both_recorded_and_digests_consistent(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            p1 = root / "primary_file.txt"
            p1.write_bytes(b"shared hardlink data")
            p2 = root / "hardlinked_file.txt"
            os.link(p1, p2)

            inv = ci.run_and_parse(root=str(root))
            self.assertIn("primary_file.txt", inv)
            self.assertIn("hardlinked_file.txt", inv)

            expected_sha = hashlib.sha256(b"shared hardlink data").hexdigest()
            self.assertEqual(inv["primary_file.txt"], expected_sha)
            self.assertEqual(inv["hardlinked_file.txt"], expected_sha)

    def test_fifo_special_file_recorded_without_reading(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            fifo_path = root / "test_named_pipe"
            try:
                os.mkfifo(fifo_path)
            except (AttributeError, OSError) as e:
                self.skipTest(f"os.mkfifo not supported: {e}")

            # Scanner must record FIFO without attempting to read it (which would hang)
            inv = ci.run_and_parse(root=str(root), timeout=5.0)
            self.assertIn("test_named_pipe", inv)
            self.assertEqual(inv["test_named_pipe"], "fifo")

    def test_mount_and_device_entries_in_parsed_inventory(self):
        entries = [
            {"kind": "mount", "mode": 0o755, "path": base64.b64encode(b"mnt/disk").decode("ascii")},
            {"kind": "fifo", "mode": 0o600, "path": base64.b64encode(b"pipe").decode("ascii")},
            {"kind": "socket", "mode": 0o666, "path": base64.b64encode(b"sock").decode("ascii")},
            {"kind": "char", "rdev": 123, "mode": 0o660, "path": base64.b64encode(b"chardev").decode("ascii")},
            {"kind": "block", "rdev": 456, "mode": 0o660, "path": base64.b64encode(b"blkdev").decode("ascii")},
        ]
        framed = _make_framed_payload(entries)
        inv = ci.parse_inventory(framed)
        self.assertEqual(inv["mnt/disk"], "mount")
        self.assertEqual(inv["pipe"], "fifo")
        self.assertEqual(inv["sock"], "socket")
        self.assertEqual(inv["chardev"], "char:123")
        self.assertEqual(inv["blkdev"], "block:456")


class ClientInventoryPruningAndExclusionsTests(unittest.TestCase):
    """Test same-device prunes (proc, sys, dev, run, tmp, srv/rs9) and package manager exclusions."""

    def test_pruning_system_directories(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            # Pruned paths
            for pruned in ["proc", "sys", "dev", "run", "tmp", "srv/rs9"]:
                p = root / pruned / "inner_file.txt"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"pruned content")

            # Legitimate unpruned paths
            (root / "srv" / "other").mkdir(parents=True, exist_ok=True)
            (root / "srv" / "other" / "keep.txt").write_bytes(b"keep content")
            (root / "usr" / "bin").mkdir(parents=True, exist_ok=True)
            (root / "usr" / "bin" / "app").write_bytes(b"app content")

            inv = ci.run_and_parse(root=str(root))

            for pruned in ["proc", "sys", "dev", "run", "tmp", "srv/rs9", "proc/inner_file.txt", "srv/rs9/inner_file.txt"]:
                self.assertNotIn(pruned, inv)

            self.assertIn("srv", inv)
            self.assertIn("srv/other", inv)
            self.assertIn("srv/other/keep.txt", inv)
            self.assertIn("usr/bin/app", inv)

    def test_package_family_exclusions(self):
        entries = [
            {"kind": "dir", "mode": 0o755, "path": base64.b64encode(b"var/lib/dpkg").decode("ascii")},
            {"kind": "file", "mode": 0o644, "path": base64.b64encode(b"var/lib/dpkg/status").decode("ascii"), "sha256": "a" * 64, "size": 10},
            {"kind": "file", "mode": 0o644, "path": base64.b64encode(b"etc/ld.so.cache").decode("ascii"), "sha256": "b" * 64, "size": 10},
            {"kind": "file", "mode": 0o644, "path": base64.b64encode(b"var/lib/dnf/history.sqlite").decode("ascii"), "sha256": "c" * 64, "size": 10},
            {"kind": "file", "mode": 0o644, "path": base64.b64encode(b"etc/pacman.d/gnupg/pubring.gpg").decode("ascii"), "sha256": "d" * 64, "size": 10},
            {"kind": "file", "mode": 0o755, "path": base64.b64encode(b"usr/bin/rs9_tool").decode("ascii"), "sha256": "e" * 64, "size": 10},
        ]
        framed = _make_framed_payload(entries)

        apt_inv = ci.parse_inventory(framed, exclusion="apt")
        self.assertNotIn("var/lib/dpkg", apt_inv)
        self.assertNotIn("var/lib/dpkg/status", apt_inv)
        self.assertNotIn("etc/ld.so.cache", apt_inv)
        self.assertIn("var/lib/dnf/history.sqlite", apt_inv)
        self.assertIn("usr/bin/rs9_tool", apt_inv)

        dnf_inv = ci.parse_inventory(framed, exclusion="dnf")
        self.assertNotIn("var/lib/dnf/history.sqlite", dnf_inv)
        self.assertIn("var/lib/dpkg/status", dnf_inv)
        self.assertIn("usr/bin/rs9_tool", dnf_inv)

        pacman_inv = ci.parse_inventory(framed, exclusion="pacman")
        self.assertNotIn("etc/pacman.d/gnupg/pubring.gpg", pacman_inv)
        self.assertIn("var/lib/dpkg/status", pacman_inv)
        self.assertIn("usr/bin/rs9_tool", pacman_inv)

    def test_exclusion_callback_without_backslash_folding(self):
        # A file with backslash in filename: var/lib/dpkg\file
        # If backslashes were folded to slashes, it would match var/lib/dpkg/file and be excluded!
        # With exact path matching, it is preserved.
        raw_path = b"var/lib/dpkg\\not_a_subdir"
        entries = [
            {"kind": "file", "mode": 0o644, "path": base64.b64encode(raw_path).decode("ascii"), "sha256": "f" * 64, "size": 10},
        ]
        framed = _make_framed_payload(entries)
        inv = ci.parse_inventory(framed, exclusion="apt")
        # Must NOT be excluded because backslashes are not folded
        self.assertIn("var/lib/dpkg\\not_a_subdir", inv)

        # Custom callback verification
        seen_paths = []
        def custom_cb(p: str) -> bool:
            seen_paths.append(p)
            return p.endswith(".drop")

        entries2 = [
            {"kind": "file", "mode": 0o644, "path": base64.b64encode(b"keep.me").decode("ascii"), "sha256": "1" * 64, "size": 10},
            {"kind": "file", "mode": 0o644, "path": base64.b64encode(b"remove.drop").decode("ascii"), "sha256": "2" * 64, "size": 10},
        ]
        framed2 = _make_framed_payload(entries2)
        inv2 = ci.parse_inventory(framed2, exclusion=custom_cb)
        self.assertEqual(seen_paths, ["keep.me", "remove.drop"])
        self.assertIn("keep.me", inv2)
        self.assertNotIn("remove.drop", inv2)


class ClientInventoryCompareAndModesTests(unittest.TestCase):
    """Test compare_inventories integration and symmetric mode comparison."""

    def test_compare_inventories_round_trip(self):
        before = {
            "usr/bin/app": "a" * 64,
            "usr/bin/old": "b" * 64,
            "etc": "dir",
        }
        after = {
            "usr/bin/app": "a" * 64,       # Unchanged
            "usr/bin/new": "c" * 64,       # Added
            # usr/bin/old removed
            "etc": "dir",
        }
        res = ci.compare_inventories(before, after)
        self.assertFalse(res["clean"])
        self.assertEqual(res["added"], ["usr/bin/new"])
        self.assertEqual(res["removed"], ["usr/bin/old"])
        self.assertEqual(res["modified"], [])

        # Clean comparison
        self.assertTrue(ci.compare_inventories(before, before)["clean"])

    def test_symmetric_mode_comparison_detects_permission_changes(self):
        entry1 = {"kind": "file", "mode": 0o644, "path": base64.b64encode(b"app").decode("ascii"), "sha256": "a" * 64, "size": 10}
        entry2 = {"kind": "file", "mode": 0o755, "path": base64.b64encode(b"app").decode("ascii"), "sha256": "a" * 64, "size": 10}

        inv_before = ci.parse_inventory(_make_framed_payload([entry1]), with_modes=True)
        inv_after = ci.parse_inventory(_make_framed_payload([entry2]), with_modes=True)

        self.assertEqual(inv_before["app"], f"{'a' * 64}:0644")
        self.assertEqual(inv_after["app"], f"{'a' * 64}:0755")

        diff = ci.compare_inventories(inv_before, inv_after)
        self.assertFalse(diff["clean"])
        self.assertEqual(diff["modified"], ["app"])


class ClientInventoryAdverseParserTests(unittest.TestCase):
    """Test adverse conditions: truncation, chatter, unknown fields, duplicates, ordering, bounds."""

    def test_empty_symlink_target_fails_closed(self):
        row = {"kind": "symlink", "mode": 0o777,
               "path": base64.b64encode(b"link").decode("ascii"), "target": ""}
        with self.assertRaises(ContractError) as caught:
            ci.parse_inventory(_make_framed_payload([row]))
        self.assertEqual(caught.exception.code, "INVENTORY_PARSE")

    def test_nonbyte_or_missing_stderr_receipt_fails_closed(self):
        from types import SimpleNamespace
        for stderr in ("scanner error", "", None, 0):
            receipt = SimpleNamespace(returncode=0, stdout=_make_framed_payload([]), stderr=stderr)
            with self.subTest(stderr=stderr):
                with self.assertRaises(ContractError) as caught:
                    ci.run_and_parse(runner=lambda argv: receipt)
                self.assertEqual(caught.exception.code, "INVENTORY_FAILED")
        with self.assertRaises(ContractError):
            ci.run_and_parse(runner=lambda argv: SimpleNamespace(returncode=0, stdout=_make_framed_payload([])))

    def test_chatter_before_or_after_frame_fails_closed(self):
        valid = _make_framed_payload([])

        # Leading chatter
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(b"Welcome to Ubuntu!\n" + valid)
        self.assertEqual(ctx.exception.code, "INVENTORY_PARSE")

        # Trailing chatter
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(valid + b"Some trailing log message\n")
        self.assertEqual(ctx.exception.code, "INVENTORY_PARSE")

        # Missing begin frame
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(b"{}\n" + ci.FRAME_END + b"\n")
        self.assertEqual(ctx.exception.code, "INVENTORY_PARSE")

        # Truncated end frame
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(ci.FRAME_BEGIN + b"\n{}\n")
        self.assertEqual(ctx.exception.code, "INVENTORY_PARSE")

    def test_bounds_limits_fail_closed(self):
        valid = _make_framed_payload([])

        # Max stdout bytes
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(valid, max_stdout_bytes=10)
        self.assertEqual(ctx.exception.code, "INVENTORY_LIMIT")

        # Max entries
        entries = [
            {"kind": "dir", "mode": 0o755, "path": base64.b64encode(b"d1").decode("ascii")},
            {"kind": "dir", "mode": 0o755, "path": base64.b64encode(b"d2").decode("ascii")},
        ]
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(_make_framed_payload(entries), max_entries=1)
        self.assertEqual(ctx.exception.code, "INVENTORY_LIMIT")

        # Single file size limit
        file_entry = [
            {"kind": "file", "mode": 0o644, "path": base64.b64encode(b"f1").decode("ascii"), "sha256": "1" * 64, "size": 100},
        ]
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(_make_framed_payload(file_entry), max_single_file_bytes=50)
        self.assertEqual(ctx.exception.code, "INVENTORY_LIMIT")

        # Total hashed bytes limit
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(_make_framed_payload(file_entry), max_total_hashed_bytes=50)
        self.assertEqual(ctx.exception.code, "INVENTORY_LIMIT")

    def test_schema_and_unknown_fields_fail_closed(self):
        # Unknown schema
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(_make_framed_payload([], schema="rs9.unknown.v1"))
        self.assertEqual(ctx.exception.code, "INVENTORY_SCHEMA")

        # Unknown version
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(_make_framed_payload([], version=1))
        self.assertEqual(ctx.exception.code, "INVENTORY_SCHEMA")

        # Unknown top-level field
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(_make_framed_payload([], extra_top_fields={"rogue_field": True}))
        self.assertEqual(ctx.exception.code, "INVENTORY_SCHEMA")

        # Unknown entry field
        bad_entry = [{"kind": "dir", "mode": 0o755, "path": base64.b64encode(b"d").decode("ascii"), "extra": 1}]
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(_make_framed_payload(bad_entry))
        self.assertEqual(ctx.exception.code, "INVENTORY_SCHEMA")

        # Unknown entry kind
        bad_kind = [{"kind": "alien", "mode": 0o755, "path": base64.b64encode(b"d").decode("ascii")}]
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(_make_framed_payload(bad_kind))
        self.assertEqual(ctx.exception.code, "INVENTORY_SCHEMA")

    def test_entry_count_and_total_bytes_mismatch_fail_closed(self):
        entries = [
            {"kind": "file", "mode": 0o644, "path": base64.b64encode(b"f").decode("ascii"), "sha256": "a" * 64, "size": 10},
        ]
        # Declared count 2, actual 1
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(_make_framed_payload(entries, entry_count=2))
        self.assertEqual(ctx.exception.code, "INVENTORY_PARSE")

        # Declared total bytes 999, actual 10
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(_make_framed_payload(entries, total_hashed_bytes=999))
        self.assertEqual(ctx.exception.code, "INVENTORY_PARSE")

    def test_duplicates_and_ordering_fail_closed(self):
        e1 = {"kind": "dir", "mode": 0o755, "path": base64.b64encode(b"same_path").decode("ascii")}
        e2 = {"kind": "dir", "mode": 0o755, "path": base64.b64encode(b"same_path").decode("ascii")}

        # Duplicate paths
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(_make_framed_payload([e1, e2], sort_entries=False))
        self.assertEqual(ctx.exception.code, "INVENTORY_DUPLICATE")

        # Unsorted entries
        ea = {"kind": "dir", "mode": 0o755, "path": base64.b64encode(b"b_dir").decode("ascii")}
        eb = {"kind": "dir", "mode": 0o755, "path": base64.b64encode(b"a_dir").decode("ascii")}
        with self.assertRaises(ContractError) as ctx:
            ci.parse_inventory(_make_framed_payload([ea, eb], sort_entries=False))
        self.assertEqual(ctx.exception.code, "INVENTORY_ORDERING")

    def test_noncanonical_base64_fails_closed(self):
        for bad_b64 in ["aGVsbG8", "aGVsbG9=", "aGVsbG8-", "!@#$"]:
            bad_entry = [{"kind": "dir", "mode": 0o755, "path": bad_b64}]
            with self.subTest(bad=bad_b64), self.assertRaises(ContractError) as ctx:
                ci.parse_inventory(_make_framed_payload(bad_entry, sort_entries=False))
            self.assertEqual(ctx.exception.code, "INVENTORY_BASE64")

    def test_path_traversal_fails_closed(self):
        bad_paths = [
            b"",
            b"/etc/passwd",
            b"../foo",
            b"foo/../bar",
            b"./foo",
            b"foo/./bar",
            b"foo//bar",
            b"foo\0bar",
        ]
        for bad in bad_paths:
            b64 = base64.b64encode(bad).decode("ascii")
            entry = [{"kind": "dir", "mode": 0o755, "path": b64}]
            with self.subTest(bad=bad), self.assertRaises(ContractError) as ctx:
                ci.parse_inventory(_make_framed_payload(entry, sort_entries=False))
            self.assertEqual(ctx.exception.code, "INVENTORY_PATH_TRAVERSAL")


class ClientInventoryScannerFailuresTests(unittest.TestCase):
    def test_raw_invalid_utf8_path_roundtrip_where_supported(self):
        with tempfile.TemporaryDirectory() as td:
            root = os.fsencode(td)
            name = b"raw-\xff-name"
            try:
                fd = os.open(root + b"/" + name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except OSError:
                self.skipTest("host filesystem rejects invalid UTF-8 filename bytes; parser fixture covers them")
            with os.fdopen(fd, "wb") as stream:
                stream.write(b"raw bytes")
            inv = ci.run_and_parse(root=td, timeout=5)
            self.assertEqual(inv[name.decode("utf-8", "surrogateescape")], hashlib.sha256(b"raw bytes").hexdigest())

    def test_boolean_protocol_version_is_rejected(self):
        with self.assertRaises(ContractError):
            ci.parse_inventory(_make_framed_payload([], extra_top_fields={"version": True}))

    def test_same_size_file_change_during_hash_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            (root / "app").write_bytes(b"original")
            injection = '''import os,sys
original_read=os.read
changed=False
def changing_read(fd,count):
    global changed
    data=original_read(fd,count)
    if data and not changed:
        changed=True
        with open(os.path.join(sys.argv[1], "app"), "r+b") as stream:
            stream.write(b"modified")
    return data
os.read=changing_read
'''
            argv = ci.scanner_argv(root)
            argv[5] = injection + argv[5]
            result = subprocess.run(argv, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stderr)["cause"], "scanner-file-changed-while-hashing")
            self.assertEqual(result.stdout, b"")

    def test_scanner_entry_file_and_output_bounds_are_enforced(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            (root / "app").write_bytes(b"bounded fixture")
            for setting, value in (("MAX_ENTRIES", ci.MAX_ENTRIES), ("MAX_SINGLE_FILE_BYTES", ci.MAX_SINGLE_FILE_BYTES),
                                   ("MAX_TOTAL_HASHED_BYTES", ci.MAX_TOTAL_HASHED_BYTES), ("MAX_STDOUT_BYTES", ci.MAX_STDOUT_BYTES)):
                argv = ci.scanner_argv(root)
                argv[5] = argv[5].replace(f"{setting} = {value}", f"{setting} = 0")
                with self.subTest(setting=setting):
                    result = subprocess.run(argv, capture_output=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b"")

    def test_socket_and_arbitrary_symlink_targets_are_never_read(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            os.symlink("target\nwith\\backslash -> spaces", root / "link")
            self.assertEqual(ci.run_and_parse(root=root, timeout=5)["link"], "symlink:target\nwith\\backslash -> spaces")
            with socket.socket(socket.AF_UNIX) as sock:
                try:
                    sock.bind(str(root / "sock"))
                except PermissionError:
                    self.skipTest("sandbox denies local socket creation; socket record grammar tested separately")
                inv = ci.run_and_parse(root=root, timeout=5)
                self.assertEqual(inv["sock"], "socket")
                self.assertEqual(inv["link"], "symlink:target\nwith\\backslash -> spaces")

    def test_legacy_gnu_transcripts_are_fixtures_and_new_transport_round_trips(self):
        # Controlled GNU sha256sum transcript fixture, not the manager script
        # execution or the unknown original Arch inventory line.
        for name in ("embedded\nnewline", "embedded\\backslash"):
            escaped = name.replace("\\", "\\\\").replace("\n", "\\n")
            transcript = "\\" + "a" * 64 + "  ./" + escaped + "\n"
            import re
            self.assertIsNone(re.fullmatch(r"([0-9a-f]{64})  (.+)", transcript.rstrip("\n")))
            row = {"kind": "file", "path": base64.b64encode(name.encode()).decode(), "mode": 0o644,
                   "size": 0, "sha256": "a" * 64}
            self.assertIn(name, ci.parse_inventory(_make_framed_payload([row])))

    def test_hash_length_and_noncanonical_frame_mutations_fail(self):
        valid = _make_framed_payload([])
        for mutation in (valid.replace(b"\n{", b"\n {"), valid[:-1], valid.replace(b'"version":2', b'"version":1')):
            with self.subTest(mutation=mutation[:40]), self.assertRaises(ContractError):
                ci.parse_inventory(mutation)

    """Test scanner errors, race conditions, and runner exit code handling."""

    def test_scanner_nonzero_exit_code_fails_closed(self):
        # Non-existent root directory causes scanner to fail with code 1
        with self.assertRaises(ContractError) as ctx:
            ci.run_and_parse(root="/non_existent_path_rs9_12345")
        self.assertEqual(ctx.exception.code, "INVENTORY_FAILED")

    def test_mock_runner_dispatch_and_exit_code(self):
        # Runner with exec method returning error
        mock_runner = Mock()
        mock_receipt = Mock(exit_code=1, stdout_bytes=b"")
        mock_runner.exec.return_value = mock_receipt

        with self.assertRaises(ContractError) as ctx:
            ci.run_and_parse(runner=mock_runner)
        self.assertEqual(ctx.exception.code, "INVENTORY_FAILED")

        # Runner with run method returning error
        mock_runner2 = Mock(spec=["run"])
        mock_receipt2 = Mock(exit_code=2, stdout_bytes=b"")
        mock_runner2.run.return_value = mock_receipt2

        with self.assertRaises(ContractError) as ctx:
            ci.run_and_parse(runner=mock_runner2)
        self.assertEqual(ctx.exception.code, "INVENTORY_FAILED")

        # Successful mock runner
        good_payload = _make_framed_payload([])
        mock_good = Mock()
        mock_good.exec.return_value = Mock(exit_code=0, stdout_bytes=good_payload, stderr_bytes=b"")
        res = ci.run_and_parse(runner=mock_good)
        self.assertEqual(res, {})

    def test_scanner_race_protection_fails_closed(self):
        # Verify that scanner fails closed (non-zero exit) if a file is not a regular file when opened
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            # If root is a file rather than a directory, opening root fails
            file_root = root / "file_not_dir"
            file_root.write_bytes(b"data")
            with self.assertRaises(ContractError) as ctx:
                ci.run_and_parse(root=str(file_root))
            self.assertEqual(ctx.exception.code, "INVENTORY_FAILED")


class LegacyControlledReproducerSubstituteTests(unittest.TestCase):
    """Test-local substitute demonstrating scanner integration with client manager flow."""

    def test_controlled_reproducer_substitute_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            (root / "etc").mkdir()
            (root / "etc" / "sample.conf").write_bytes(b"initial configuration\n")

            # Emulate before snapshot
            before = ci.run_and_parse(root=str(root))
            self.assertEqual(before["etc/sample.conf"], hashlib.sha256(b"initial configuration\n").hexdigest())

            # Emulate package installation
            (root / "usr" / "bin").mkdir(parents=True)
            (root / "usr" / "bin" / "daemon").write_bytes(b"installed binary\n")

            # Emulate after snapshot
            after = ci.run_and_parse(root=str(root))

            comparison = ci.compare_inventories(before, after)
            self.assertFalse(comparison["clean"])
            self.assertIn("usr/bin/daemon", comparison["added"])

            # Emulate partial package removal (leaving leftover parent directory usr)
            (root / "usr" / "bin" / "daemon").unlink()
            (root / "usr" / "bin").rmdir()

            # Emulate post-purge snapshot with leftover directory
            leftover_post = ci.run_and_parse(root=str(root))
            leftover_comp = ci.compare_inventories(before, leftover_post)
            self.assertFalse(leftover_comp["clean"])
            self.assertEqual(leftover_comp["added"], ["usr"])

            # Clean up the leftover directory
            (root / "usr").rmdir()
            final_post = ci.run_and_parse(root=str(root))
            final_comparison = ci.compare_inventories(before, final_post)
            self.assertTrue(final_comparison["clean"])
            self.assertEqual(final_comparison["added"], [])
            self.assertEqual(final_comparison["removed"], [])
            self.assertEqual(final_comparison["modified"], [])


class ClientInventoryDiagnosticsAndPruningTests(unittest.TestCase):
    """Test scanner diagnostics framing, strict parser validation, and pruned vs unpruned equality."""

    def test_strict_diagnostics_validation_and_rejection_of_malformed_structures(self):
        def valid_diag():
            return {
                "counters": {
                    "dir_count": 1,
                    "entries": 2,
                    "file_count": 1,
                    "hardlink_count": 0,
                    "special_count": 0,
                    "symlink_count": 0,
                    "total_hashed_bytes": 10, "scanned_entries": 2, "excluded_files": 0,
                },
                "max": {
                    "depth": 1, "directory_entries": 2,
                    "file_bytes": 10,
                    "path_bytes": 15,
                    "symlink_bytes": 0,
                },
            }

        entries = [
            {"kind": "dir", "mode": 0o755, "path": base64.b64encode(b"d").decode()},
            {"kind": "file", "mode": 0o644, "path": base64.b64encode(b"d/f").decode(), "sha256": "0" * 64, "size": 10},
        ]

        # Valid payload with diagnostics parses cleanly and return_diagnostics works
        framed = _make_framed_payload(entries, extra_top_fields={"diagnostics": valid_diag()})
        inv, diag = ci.parse_inventory(framed, return_diagnostics=True)
        self.assertEqual(len(inv), 2)
        self.assertEqual(diag["counters"]["entries"], 2)

        # 1. Non-dict diagnostics
        for bad in ("bad", [1, 2], True, 123):
            with self.subTest(bad=bad), self.assertRaises(ContractError) as caught:
                ci.parse_inventory(_make_framed_payload(entries, extra_top_fields={"diagnostics": bad}))
            self.assertEqual(caught.exception.code, "INVENTORY_SCHEMA")

        # 2. Missing top keys or unknown keys in diagnostics
        d_missing = valid_diag()
        del d_missing["max"]
        with self.assertRaises(ContractError) as caught:
            ci.parse_inventory(_make_framed_payload(entries, extra_top_fields={"diagnostics": d_missing}))
        self.assertEqual(caught.exception.code, "INVENTORY_SCHEMA")

        d_extra = valid_diag()
        d_extra["rogue"] = 123
        with self.assertRaises(ContractError) as caught:
            ci.parse_inventory(_make_framed_payload(entries, extra_top_fields={"diagnostics": d_extra}))
        self.assertEqual(caught.exception.code, "INVENTORY_SCHEMA")

        # 3. Bad keys in counters
        d_cnt_missing = valid_diag()
        del d_cnt_missing["counters"]["special_count"]
        with self.assertRaises(ContractError) as caught:
            ci.parse_inventory(_make_framed_payload(entries, extra_top_fields={"diagnostics": d_cnt_missing}))
        self.assertEqual(caught.exception.code, "INVENTORY_SCHEMA")

        d_cnt_extra = valid_diag()
        d_cnt_extra["counters"]["rogue"] = 0
        with self.assertRaises(ContractError) as caught:
            ci.parse_inventory(_make_framed_payload(entries, extra_top_fields={"diagnostics": d_cnt_extra}))
        self.assertEqual(caught.exception.code, "INVENTORY_SCHEMA")

        # 4. Invalid types / negatives in counters
        for bad_val in (-1, "two", 1.5, True, False):
            d_bad = valid_diag()
            d_bad["counters"]["file_count"] = bad_val
            with self.subTest(bad_val=bad_val), self.assertRaises(ContractError) as caught:
                ci.parse_inventory(_make_framed_payload(entries, extra_top_fields={"diagnostics": d_bad}))
            self.assertEqual(caught.exception.code, "INVENTORY_SCHEMA")

        # 5. Counter value mismatches
        # entries counter != entry_count
        d_cnt_mis = valid_diag()
        d_cnt_mis["counters"]["entries"] = 99
        with self.assertRaises(ContractError) as caught:
            ci.parse_inventory(_make_framed_payload(entries, extra_top_fields={"diagnostics": d_cnt_mis}))
        self.assertEqual(caught.exception.code, "INVENTORY_PARSE")

        # total_hashed_bytes mismatch
        d_cnt_mis = valid_diag()
        d_cnt_mis["counters"]["total_hashed_bytes"] = 99
        with self.assertRaises(ContractError) as caught:
            ci.parse_inventory(_make_framed_payload(entries, extra_top_fields={"diagnostics": d_cnt_mis}))
        self.assertEqual(caught.exception.code, "INVENTORY_PARSE")

        # file_count mismatch
        d_cnt_mis = valid_diag()
        d_cnt_mis["counters"]["file_count"] = 0
        with self.assertRaises(ContractError) as caught:
            ci.parse_inventory(_make_framed_payload(entries, extra_top_fields={"diagnostics": d_cnt_mis}))
        self.assertEqual(caught.exception.code, "INVENTORY_PARSE")

        # dir_count mismatch
        d_cnt_mis = valid_diag()
        d_cnt_mis["counters"]["dir_count"] = 0
        with self.assertRaises(ContractError) as caught:
            ci.parse_inventory(_make_framed_payload(entries, extra_top_fields={"diagnostics": d_cnt_mis}))
        self.assertEqual(caught.exception.code, "INVENTORY_PARSE")

        # 6. Bad keys in max
        d_max_missing = valid_diag()
        del d_max_missing["max"]["depth"]
        with self.assertRaises(ContractError) as caught:
            ci.parse_inventory(_make_framed_payload(entries, extra_top_fields={"diagnostics": d_max_missing}))
        self.assertEqual(caught.exception.code, "INVENTORY_SCHEMA")

        # 7. Max limit violations
        for field, bad_limit in [
            ("depth", ci.MAX_DEPTH + 1),
            ("file_bytes", ci.MAX_SINGLE_FILE_BYTES + 1),
            ("path_bytes", ci.MAX_PATH_BYTES + 1),
            ("symlink_bytes", ci.MAX_SYMLINK_TARGET_BYTES + 1),
        ]:
            d_over = valid_diag()
            d_over["max"][field] = bad_limit
            with self.subTest(field=field), self.assertRaises(ContractError) as caught:
                ci.parse_inventory(_make_framed_payload(entries, extra_top_fields={"diagnostics": d_over}))
            self.assertEqual(caught.exception.code, "INVENTORY_LIMIT")

    def test_pruned_and_unpruned_equality_including_newline_and_nonutf8(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()

            # Normal files and directories
            (root / "usr" / "bin").mkdir(parents=True)
            (root / "usr" / "bin" / "app").write_bytes(b"app content\n")
            (root / "etc").mkdir(parents=True)
            (root / "etc" / "app.conf").write_bytes(b"app config\n")

            # Symlink
            os.symlink("app", root / "usr" / "bin" / "app_link")

            # Newline filename and newline directory
            (root / "usr" / "bin" / "file\nwith\nnewline").write_bytes(b"newline file content\n")
            nl_dir = root / "etc" / "dir\nwith\nnewline"
            nl_dir.mkdir(parents=True)
            (nl_dir / "child.conf").write_bytes(b"child in newline dir\n")

            # Non-UTF8 filename
            raw_name = b"raw_\xff\xfe_data.bin"
            try:
                raw_path = root / "usr" / "bin" / raw_name.decode("utf-8", errors="surrogateescape")
                raw_path.write_bytes(b"raw nonutf8 content\n")
                has_nonutf8_file = True
            except OSError:
                has_nonutf8_file = False

            # PRUNES directory: tmp/, run/, srv/rs9/
            (root / "tmp").mkdir(parents=True)
            (root / "tmp" / "should_be_pruned.txt").write_bytes(b"ephemeral tmp data")
            (root / "run").mkdir(parents=True)
            (root / "run" / "pid.txt").write_bytes(b"pid")
            (root / "srv" / "rs9").mkdir(parents=True)
            (root / "srv" / "rs9" / "internal.bin").write_bytes(b"internal")

            # var/log: package log files are excluded
            (root / "var" / "log" / "apt").mkdir(parents=True)
            (root / "var" / "log" / "apt" / "history.log").write_bytes(b"apt log data 12345\n" * 100)
            (root / "var" / "log" / "dpkg.log").write_bytes(b"dpkg log data 12345\n" * 100)

            # var/lib and var/cache: mixed directories containing BOTH excluded package state
            # and non-excluded application data. True subtree pruning is impossible here!
            (root / "var" / "lib" / "dpkg").mkdir(parents=True)
            (root / "var" / "lib" / "dpkg" / "status").write_bytes(b"Package: test\n" * 50)
            (root / "var" / "lib" / "other").mkdir(parents=True)
            (root / "var" / "lib" / "other" / "app_data.txt").write_bytes(b"unexcluded user app data\n")

            (root / "var" / "cache" / "apt" / "archives").mkdir(parents=True)
            (root / "var" / "cache" / "apt" / "archives" / "test.deb").write_bytes(b"deb binary payload\n" * 500)
            (root / "var" / "cache" / "other").mkdir(parents=True)
            (root / "var" / "cache" / "other" / "cached.dat").write_bytes(b"unexcluded cache data\n")

            (root / "var/lib/dpkg" / "a\nb").write_bytes(b"required newline identity")
            # 1. Run scanner with family="apt" (PRUNED: skips hashing proven excluded files)
            pruned_argv = ci.scanner_argv(root=str(root), family="apt")
            proc_pruned = subprocess.run(pruned_argv, capture_output=True, check=True)
            pruned_inv, pruned_diag = ci.parse_inventory(proc_pruned.stdout, exclusion="apt", return_diagnostics=True)

            # 2. Run scanner with family="" (UNPRUNED: hashes all non-pruned files)
            unpruned_argv = ci.scanner_argv(root=str(root), family="")
            proc_unpruned = subprocess.run(unpruned_argv, capture_output=True, check=True)
            unpruned_inv, unpruned_diag = ci.parse_inventory(proc_unpruned.stdout, exclusion="apt", return_diagnostics=True)

            # PROVE EXACT EQUALITY between pruned and unpruned parsed inventories
            self.assertEqual(pruned_inv, unpruned_inv)
            self.assertIn("var/lib/dpkg/a\nb", pruned_inv)

            # Unexcluded files in mixed directories must be present in both
            self.assertIn("var/lib/other/app_data.txt", pruned_inv)
            self.assertEqual(pruned_inv["var/lib/other/app_data.txt"], hashlib.sha256(b"unexcluded user app data\n").hexdigest())
            self.assertIn("var/cache/other/cached.dat", pruned_inv)
            self.assertEqual(pruned_inv["var/cache/other/cached.dat"], hashlib.sha256(b"unexcluded cache data\n").hexdigest())

            # Newline paths must be present in both
            self.assertIn("usr/bin/file\nwith\nnewline", pruned_inv)
            self.assertIn("etc/dir\nwith\nnewline/child.conf", pruned_inv)

            if has_nonutf8_file:
                raw_key = ("usr/bin/" + raw_name.decode("utf-8", errors="surrogateescape"))
                self.assertIn(raw_key, pruned_inv)

            # Excluded files must be in NEITHER inventory
            self.assertNotIn("var/log/dpkg.log", pruned_inv)
            self.assertNotIn("var/log/apt/history.log", pruned_inv)
            self.assertNotIn("var/lib/dpkg/status", pruned_inv)
            self.assertNotIn("var/cache/apt/archives/test.deb", pruned_inv)

            # Ephemeral PRUNES dirs must be in NEITHER inventory
            self.assertNotIn("tmp", pruned_inv)
            self.assertNotIn("tmp/should_be_pruned.txt", pruned_inv)
            self.assertNotIn("run", pruned_inv)
            self.assertNotIn("srv/rs9", pruned_inv)

            # PROVE that the pruned run avoided hashing excluded files
            self.assertGreater(unpruned_diag["counters"]["total_hashed_bytes"], pruned_diag["counters"]["total_hashed_bytes"])
            excluded_bytes = (
                len(b"apt log data 12345\n" * 100)
                + len(b"dpkg log data 12345\n" * 100)
                + len(b"Package: test\n" * 50)
                + len(b"deb binary payload\n" * 500)
            )
            self.assertEqual(
                unpruned_diag["counters"]["total_hashed_bytes"] - pruned_diag["counters"]["total_hashed_bytes"],
                excluded_bytes,
            )


if __name__ == "__main__":
    unittest.main()


class InventoryCapacityContracts(unittest.TestCase):
    def test_v1_or_missing_diagnostics_is_rejected(self):
        payload = {"schema": ci.FRAME_SCHEMA, "version": ci.FRAME_VERSION,
                   "entry_count": 0, "total_hashed_bytes": 0, "entries": []}
        with self.assertRaises(ContractError):
            ci.parse_inventory(ci.frame_payload(payload))
        with self.assertRaises(ContractError):
            ci.parse_inventory(_make_framed_payload([], schema="rs9.client-inventory.v1", version=1))

    def test_real_capacity_failure_preserves_safe_counters_and_stage(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "large").write_bytes(b"12345")
            argv = ci.scanner_argv(td)
            argv[5] = ci.SCANNER_SCRIPT.replace("MAX_SINGLE_FILE_BYTES = " + str(ci.MAX_SINGLE_FILE_BYTES),
                                                 "MAX_SINGLE_FILE_BYTES = 4")
            receipt = subprocess.run(argv, capture_output=True)
            self.assertNotEqual(receipt.returncode, 0)
            with self.assertRaises(ContractError) as caught:
                ci.run_and_parse(runner=lambda _: receipt, family="apt", stage="post-remove")
            details = caught.exception.details
            self.assertEqual((details["family"], details["stage"], details["cause"]),
                             ("apt", "post-remove", "file-bytes"))
            self.assertEqual((details["observed"], details["maximum"]), (5, 4))
            self.assertEqual(details["counters"]["scanned_entries"], 1)
            self.assertNotIn(td.encode(), receipt.stderr)

    def test_parser_capacity_failure_has_numeric_observed_and_maximum(self):
        entry = {"kind": "file", "mode": 0o644, "path": "Zg==", "sha256": "a"*64, "size": 5}
        with self.assertRaises(ContractError) as caught:
            ci.parse_inventory(_make_framed_payload([entry]), max_single_file_bytes=4)
        self.assertEqual(caught.exception.details, {"cause": "capacity", "limit": "file-bytes", "observed": 5, "maximum": 4})

    def test_error_diagnostics_reject_unknown_counter_keys_and_nonintegers(self):
        from rs9.errors import safe_details
        self.assertEqual(safe_details({"counters": {"private_path": 1}}), {"details_truncated": True})
        self.assertEqual(safe_details({"max": {"depth": True}}), {"details_truncated": True})
        self.assertEqual(safe_details({"observed": -1, "cause": "/private/path"}), {"details_truncated": True})

    def test_underreported_maxima_and_scanner_work_are_rejected(self):
        entry = {"kind": "file", "mode": 0o644, "path": "Zg==", "sha256": "a"*64, "size": 5}
        payload = json.loads(ci.extract_frame_body(_make_framed_payload([entry])))
        for group, key in (("max", "file_bytes"), ("max", "path_bytes"), ("counters", "scanned_entries")):
            bad = json.loads(json.dumps(payload));bad["diagnostics"][group][key] = 0
            with self.subTest(key=key), self.assertRaises(ContractError):
                ci.parse_inventory(ci.frame_payload(bad))
