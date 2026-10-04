"""Adverse tests for unconditional fail-safe rejection of tar hard links.

Hard links in archives are rejected before any member visitor runs, avoiding
silent inspection gaps, retained-memory, and logical accounting concerns, while
preserving identical safe symlink behavior and non-hardlink manifests.
"""

import io
from pathlib import Path
import tarfile
import tempfile
import unittest

from rs9.archives import inspect_archive
from rs9.errors import ContractError


def make_tar_bytes(entries):
    """Build a tar.gz archive from a list of entry specifications.

    Each entry can be:
      (name, data, mode, kind, target)
    or
      (name, data, mode, kind, target, size)
    """
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for entry in entries:
            if len(entry) == 6:
                name, data, mode, kind, target, size = entry
            else:
                name, data, mode, kind, target = entry
                size = len(data) if kind == tarfile.REGTYPE else 0
            item = tarfile.TarInfo(name)
            item.mode = mode
            item.type = kind
            item.linkname = target
            item.size = size
            stream = io.BytesIO(data) if (data and (kind == tarfile.REGTYPE or size > 0)) else None
            archive.addfile(item, stream)
    return output.getvalue()


class ArchiveHardlinkTests(unittest.TestCase):
    def inspect(self, entries, commands=None, **kwargs):
        if commands is None:
            commands = {"app": "app/bin/app"}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve() / "input.tar.gz"
            path.write_bytes(make_tar_bytes(entries))
            return inspect_archive(path, commands, **kwargs)

    def base_entries(self):
        return [
            ("app/bin/app", b"#!/bin/sh\necho hello\n", 0o755, tarfile.REGTYPE, ""),
        ]

    def test_forward_hardlink_rejected_before_visitor(self):
        """Hard link appearing before its target entry must reject without calling visitor."""
        seen = []
        entries = [
            ("app/bin/alias", b"", 0o755, tarfile.LNKTYPE, "app/bin/app"),
            ("app/bin/app", b"#!/bin/sh\necho hello\n", 0o755, tarfile.REGTYPE, ""),
        ]
        with self.assertRaises(ContractError) as ctx:
            self.inspect(entries, on_file=lambda p, b, m: seen.append(p))
        self.assertEqual(ctx.exception.code, "UNSAFE_LINK")
        self.assertEqual(seen, [])

    def test_backward_hardlink_rejected_before_visitor(self):
        """Hard link appearing after its target entry must reject without calling visitor."""
        seen = []
        entries = [
            ("app/bin/app", b"#!/bin/sh\necho hello\n", 0o755, tarfile.REGTYPE, ""),
            ("app/bin/alias", b"", 0o755, tarfile.LNKTYPE, "app/bin/app"),
        ]
        with self.assertRaises(ContractError) as ctx:
            self.inspect(entries, on_file=lambda p, b, m: seen.append(p))
        self.assertEqual(ctx.exception.code, "UNSAFE_LINK")
        self.assertEqual(seen, [])

    def test_hardlink_cycles_rejected(self):
        """Hard link cycles (self, mutual, symlink mixed) must reject without visitor."""
        cases = [
            ("self_cycle", [
                ("app/bin/app", b"#!/bin/sh\necho hello\n", 0o755, tarfile.REGTYPE, ""),
                ("app/cycle", b"", 0o644, tarfile.LNKTYPE, "app/cycle"),
            ]),
            ("mutual_cycle", [
                ("app/bin/app", b"#!/bin/sh\necho hello\n", 0o755, tarfile.REGTYPE, ""),
                ("app/a", b"", 0o644, tarfile.LNKTYPE, "app/b"),
                ("app/b", b"", 0o644, tarfile.LNKTYPE, "app/a"),
            ]),
            ("mixed_symlink_hardlink_cycle", [
                ("app/bin/app", b"#!/bin/sh\necho hello\n", 0o755, tarfile.REGTYPE, ""),
                ("app/sym", b"", 0o777, tarfile.SYMTYPE, "hard"),
                ("app/hard", b"", 0o644, tarfile.LNKTYPE, "app/sym"),
            ]),
        ]
        for name, entries in cases:
            with self.subTest(case=name):
                seen = []
                with self.assertRaises(ContractError) as ctx:
                    self.inspect(entries, on_file=lambda p, b, m: seen.append(p))
                self.assertEqual(ctx.exception.code, "UNSAFE_LINK")
                self.assertEqual(seen, [])

    def test_missing_target_hardlink_rejected(self):
        """Hard link referencing a non-existent member must reject fail-safe."""
        seen = []
        entries = self.base_entries() + [
            ("app/ghost", b"", 0o644, tarfile.LNKTYPE, "app/does_not_exist"),
        ]
        with self.assertRaises(ContractError) as ctx:
            self.inspect(entries, on_file=lambda p, b, m: seen.append(p))
        self.assertEqual(ctx.exception.code, "UNSAFE_LINK")
        self.assertEqual(seen, [])

    def test_traversal_hardlink_rejected(self):
        """Hard links attempting root escape, traversal, or malformed target reject fail-safe."""
        traversal_targets = [
            "../../outside",
            "../escape",
            "app/../../outside",
            "/etc/passwd",
            "/bin/sh",
            "app\\backslash",
        ]
        for target in traversal_targets:
            with self.subTest(target=target):
                seen = []
                entries = self.base_entries() + [
                    ("app/traversal_link", b"", 0o644, tarfile.LNKTYPE, target),
                ]
                with self.assertRaises(ContractError) as ctx:
                    self.inspect(entries, on_file=lambda p, b, m: seen.append(p))
                self.assertEqual(ctx.exception.code, "UNSAFE_LINK")
                self.assertEqual(seen, [])

    def test_hardlinked_executable_rejected(self):
        """Archives with hardlinked executables (direct command or alias) reject fail-safe."""
        seen = []
        entries_cmd_is_link = [
            ("app/bin/real_binary", b"#!/bin/sh\necho real\n", 0o755, tarfile.REGTYPE, ""),
            ("app/bin/app", b"", 0o755, tarfile.LNKTYPE, "app/bin/real_binary"),
        ]
        with self.assertRaises(ContractError) as ctx:
            self.inspect(entries_cmd_is_link, on_file=lambda p, b, m: seen.append(p))
        self.assertEqual(ctx.exception.code, "UNSAFE_LINK")
        self.assertEqual(seen, [])

        seen_alias = []
        entries_cmd_has_link = self.base_entries() + [
            ("app/bin/app_hardlink", b"", 0o755, tarfile.LNKTYPE, "app/bin/app"),
        ]
        with self.assertRaises(ContractError) as ctx:
            self.inspect(entries_cmd_has_link, on_file=lambda p, b, m: seen_alias.append(p))
        self.assertEqual(ctx.exception.code, "UNSAFE_LINK")
        self.assertEqual(seen_alias, [])

    def test_hardlinked_script_rejected(self):
        """Archives containing hardlinked scripts reject before any inspection or visitor."""
        seen = []
        entries = self.base_entries() + [
            ("app/scripts/runner.sh", b"#!/bin/bash\nexit 0\n", 0o755, tarfile.REGTYPE, ""),
            ("app/scripts/alias.sh", b"", 0o755, tarfile.LNKTYPE, "app/scripts/runner.sh"),
        ]
        with self.assertRaises(ContractError) as ctx:
            self.inspect(entries, on_file=lambda p, b, m: seen.append(p))
        self.assertEqual(ctx.exception.code, "UNSAFE_LINK")
        self.assertEqual(seen, [])

    def test_hardlinked_license_rejected(self):
        """Archives containing hardlinked license/notice files reject fail-safe."""
        seen = []
        entries = self.base_entries() + [
            ("app/LICENSE", b"Apache-2.0 license text", 0o644, tarfile.REGTYPE, ""),
            ("app/NOTICE", b"", 0o644, tarfile.LNKTYPE, "app/LICENSE"),
        ]
        with self.assertRaises(ContractError) as ctx:
            self.inspect(entries, on_file=lambda p, b, m: seen.append(p))
        self.assertEqual(ctx.exception.code, "UNSAFE_LINK")
        self.assertEqual(seen, [])

    def test_hardlinked_evidence_rejected(self):
        """Archives containing hardlinked package or evidence files reject fail-safe."""
        seen = []
        entries = [
            ("package/package.json", b'{"name": "test", "version": "1.0.0"}', 0o644, tarfile.REGTYPE, ""),
            ("package/metadata.json", b"", 0o644, tarfile.LNKTYPE, "package/package.json"),
        ]
        with self.assertRaises(ContractError) as ctx:
            self.inspect(entries, commands={}, on_file=lambda p, b, m: seen.append(p))
        self.assertEqual(ctx.exception.code, "UNSAFE_LINK")
        self.assertEqual(seen, [])

    def test_hardlink_size_and_accounting_rejected(self):
        """Hard links with zero size, non-zero size, excessive size, or negative size reject fail-safe.

        Ensures no decompression ratio bypass, size accounting evasion, or retained memory.
        """
        cases = [
            ("zero_size_hardlink", [
                ("app/bin/app", b"x" * 4096, 0o755, tarfile.REGTYPE, ""),
                ("app/link_zero", b"", 0o644, tarfile.LNKTYPE, "app/bin/app", 0),
            ]),
            ("nonzero_size_hardlink", [
                ("app/bin/app", b"x" * 4096, 0o755, tarfile.REGTYPE, ""),
                ("app/link_nonzero", b"y" * 1024, 0o644, tarfile.LNKTYPE, "app/bin/app", 1024),
            ]),
            ("huge_size_hardlink", [
                ("app/bin/app", b"x" * 4096, 0o755, tarfile.REGTYPE, ""),
                ("app/link_huge", b"", 0o644, tarfile.LNKTYPE, "app/bin/app", 300 * 1024 * 1024),
            ]),
            ("negative_size_hardlink", [
                ("app/bin/app", b"x" * 4096, 0o755, tarfile.REGTYPE, ""),
                ("app/link_neg", b"", 0o644, tarfile.LNKTYPE, "app/bin/app", -1),
            ]),
            ("many_hardlinks_amplification", [
                ("app/bin/app", b"executable payload", 0o755, tarfile.REGTYPE, ""),
            ] + [
                (f"app/copy_{i}", b"", 0o644, tarfile.LNKTYPE, "app/bin/app", 0) for i in range(25)
            ]),
        ]
        for name, entries in cases:
            with self.subTest(case=name):
                seen = []
                with self.assertRaises(ContractError) as ctx:
                    self.inspect(entries, on_file=lambda p, b, m: seen.append(p))
                self.assertEqual(ctx.exception.code, "UNSAFE_LINK")
                self.assertEqual(seen, [])

    def test_rejection_regardless_of_on_file(self):
        """Hard link rejection occurs whether on_file visitor is provided or None."""
        entries = self.base_entries() + [
            ("app/copy", b"", 0o644, tarfile.LNKTYPE, "app/bin/app"),
        ]
        # With on_file=None
        with self.assertRaises(ContractError) as ctx1:
            self.inspect(entries, on_file=None)
        self.assertEqual(ctx1.exception.code, "UNSAFE_LINK")

        # Without on_file argument
        with self.assertRaises(ContractError) as ctx2:
            self.inspect(entries)
        self.assertEqual(ctx2.exception.code, "UNSAFE_LINK")

    def test_visitor_never_called_on_rejected_archives_positional(self):
        """Verify visitor is never called whether hard link is at head, middle, or tail."""
        pos_cases = [
            ("hardlink_at_head", [
                ("app/link", b"", 0o644, tarfile.LNKTYPE, "app/target"),
                ("app/file1", b"data1", 0o644, tarfile.REGTYPE, ""),
                ("app/bin/app", b"binary", 0o755, tarfile.REGTYPE, ""),
            ]),
            ("hardlink_in_middle", [
                ("app/file1", b"data1", 0o644, tarfile.REGTYPE, ""),
                ("app/link", b"", 0o644, tarfile.LNKTYPE, "app/target"),
                ("app/bin/app", b"binary", 0o755, tarfile.REGTYPE, ""),
            ]),
            ("hardlink_at_tail", [
                ("app/file1", b"data1", 0o644, tarfile.REGTYPE, ""),
                ("app/bin/app", b"binary", 0o755, tarfile.REGTYPE, ""),
                ("app/link", b"", 0o644, tarfile.LNKTYPE, "app/target"),
            ]),
        ]
        for name, entries in pos_cases:
            with self.subTest(position=name):
                seen = []
                with self.assertRaises(ContractError) as ctx:
                    self.inspect(entries, on_file=lambda p, b, m: seen.append(p))
                self.assertEqual(ctx.exception.code, "UNSAFE_LINK")
                self.assertEqual(seen, [], f"Visitor called unexpectedly for {seen} in {name}")

    def test_safe_symlinks_and_non_hardlink_manifests_preserved(self):
        """Archives with safe symlinks and non-hardlink members behave identically."""
        seen = []
        entries = self.base_entries() + [
            ("app/current", b"", 0o777, tarfile.SYMTYPE, "bin/app"),
            ("app/data/readme.txt", b"documentation\n", 0o644, tarfile.REGTYPE, ""),
            ("app/readme_link", b"", 0o777, tarfile.SYMTYPE, "data/readme.txt"),
        ]
        result = self.inspect(entries, on_file=lambda p, b, m: seen.append((p, b, m)))
        self.assertEqual(result["root"], "app")
        # Visitor called only for regular files, in archive order
        self.assertEqual([p for p, b, m in seen], ["app/bin/app", "app/data/readme.txt"])
        self.assertEqual(seen[0][1], b"#!/bin/sh\necho hello\n")
        self.assertEqual(seen[0][2], 0o755)
        self.assertEqual(seen[1][1], b"documentation\n")
        self.assertEqual(seen[1][2], 0o644)

        # Output with on_file must exactly equal output without on_file
        result_no_visitor = self.inspect(entries)
        self.assertEqual(result, result_no_visitor)
        self.assertIn("manifest_sha256", result)
        self.assertEqual(len(result["manifest_sha256"]), 64)
        self.assertEqual(result["commands"], {
            "app": {"path": "app/bin/app", "sha256": result["members"][0]["sha256"],
                    "mode": result["members"][0]["mode"], "size": result["members"][0]["size"]}
        })
