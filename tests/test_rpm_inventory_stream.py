"""Tests for CONT11R1 complete bounded RPM inventory streams.

Covers:
- Reusable machine_text and machine_records with strict decoding and explicit bounds.
- Fail-closed stream validation (no prefix acceptance on decode/framing errors).
- Sanitized ContractError details with causal receipt attachment.
- Exact 16MiB reader and +1 collector limit failure without huge fixtures.
- Preservation inventory collector with authenticated archive fixtures:
  - small archive (< 64KiB)
  - dump > 64KiB, attrs < 64KiB
  - both dump and attrs > 64KiB
  - exact full rows (hashes, modes, metadata)
  - errors past 64KiB boundary (corrupt fields, duplicates, missing/extra attrs,
    invalid UTF-8, incomplete final, empty/trailing bad, non-ASCII numbers)
  - algo query 64-byte bound and exact '8\\n' requirement
  - non-query projection failure receipts must be None
  - inventory_diagnostic (<= 16KiB) attached for failures; additive receipts ledger on success
  - unchanged package/asset/closure/source bytes
"""

import json
from pathlib import Path
import re
import stat
import tempfile
import unittest

from rs9.build_native import (
    CommandReceipt,
    MockCommandRunner,
    npm_bundle,
    stage_offline_npm_closure,
    validate_build_inputs,
)
from rs9.build_rpm import _render_rpm_spec
from rs9.errors import ContractError, safe_details
from rs9.machine_stream import machine_records, machine_text
from rs9.release_core import digest
from rs9.rpm_preservation import (
    INVENTORY_SCHEMA,
    collect_preservation_inventory,
    parse_dump,
)
from tests.rpm_fixtures import fixture_members, inventory_response
from tests.test_build_native import create_cli_fixture


class MachineStreamUnitTests(unittest.TestCase):
    """Unit tests for machine_text and machine_records stream readers."""

    def test_machine_text_decodes_clean_stream(self):
        receipt = CommandReceipt(["rpm", "-q"], 0, b"line1\nline2\n", b"")
        text = machine_text(
            receipt,
            stream="stdout",
            limit=1024,
            code="RPM_INVENTORY_FAILED",
            substage="test-stream",
        )
        self.assertEqual(text, "line1\nline2\n")

    def test_machine_text_stderr_stream(self):
        receipt = CommandReceipt(["tool"], 0, b"", b"warning text\n")
        text = machine_text(
            receipt,
            stream="stderr",
            limit=1024,
            code="RPM_INVENTORY_FAILED",
            substage="test-stream",
        )
        self.assertEqual(text, "warning text\n")

    def test_machine_text_rejects_missing_receipt_and_non_bytes(self):
        with self.assertRaises(ContractError) as caught:
            machine_text(
                None,
                limit=1024,
                code="RPM_INVENTORY_FAILED",
                substage="test-stream",
            )
        self.assertEqual(caught.exception.reason_token, "receipt-missing")
        self.assertIsNone(caught.exception.receipt)

        invalid_receipt = CommandReceipt(["tool"], 0, b"", b"")
        invalid_receipt.stdout_bytes = "not-bytes"  # type: ignore
        with self.assertRaises(ContractError) as caught2:
            machine_text(
                invalid_receipt,
                limit=1024,
                code="RPM_INVENTORY_FAILED",
                substage="test-stream",
            )
        self.assertEqual(caught2.exception.reason_token, "stream-type")
        self.assertIs(caught2.exception.receipt, invalid_receipt)

    def test_machine_text_rejects_invalid_stream_name(self):
        receipt = CommandReceipt(["tool"], 0, b"out", b"err")
        with self.assertRaises(ContractError) as caught:
            machine_text(
                receipt,
                stream="invalid",  # type: ignore
                limit=1024,
                code="RPM_INVENTORY_FAILED",
                substage="test-stream",
            )
        self.assertEqual(caught.exception.reason_token, "invalid-stream")

    def test_machine_text_enforces_bounds_before_strict_decoding(self):
        # 10 invalid bytes, limit 9: limit check must fire before decode error
        invalid_oversize = b"\xff" * 10
        receipt = CommandReceipt(["tool"], 0, invalid_oversize, b"")
        with self.assertRaises(ContractError) as caught:
            machine_text(
                receipt,
                limit=9,
                code="RPM_INVENTORY_FAILED",
                substage="test-stream",
            )
        self.assertEqual(caught.exception.reason_token, "stream-limit-exceeded")
        self.assertEqual(caught.exception.stdout_length, 10)
        self.assertEqual(caught.exception.stdout_sha256, digest(invalid_oversize))

    def test_machine_text_strict_decoding_fails_closed_no_valid_prefix_acceptance(self):
        # 100 valid ASCII bytes followed by 1 invalid byte within limit
        prefix = b"a" * 100
        payload = prefix + b"\xff"
        receipt = CommandReceipt(["tool"], 0, payload, b"")
        with self.assertRaises(ContractError) as caught:
            machine_text(
                receipt,
                limit=200,
                code="RPM_INVENTORY_FAILED",
                substage="test-stream",
            )
        self.assertEqual(caught.exception.reason_token, "stream-decode-failed")
        self.assertIs(caught.exception.receipt, receipt)

    def test_machine_records_requires_newline_terminator(self):
        # No trailing newline
        receipt = CommandReceipt(["tool"], 0, b"record1\nrecord2", b"")
        with self.assertRaises(ContractError) as caught:
            machine_records(
                receipt,
                limit=1024,
                code="RPM_INVENTORY_FAILED",
                substage="test-stream",
            )
        self.assertEqual(caught.exception.reason_token, "incomplete-framing")

        # Empty stream has no trailing newline
        receipt_empty = CommandReceipt(["tool"], 0, b"", b"")
        with self.assertRaises(ContractError) as caught_empty:
            machine_records(
                receipt_empty,
                limit=1024,
                code="RPM_INVENTORY_FAILED",
                substage="test-stream",
            )
        self.assertEqual(caught_empty.exception.reason_token, "incomplete-framing")

    def test_machine_records_rejects_empty_records(self):
        # Consecutive newlines
        receipt = CommandReceipt(["tool"], 0, b"rec1\n\nrec2\n", b"")
        with self.assertRaises(ContractError) as caught:
            machine_records(
                receipt,
                limit=1024,
                code="RPM_INVENTORY_FAILED",
                substage="test-stream",
            )
        self.assertEqual(caught.exception.reason_token, "empty-record")

        # Only newline
        receipt_nl = CommandReceipt(["tool"], 0, b"\n", b"")
        with self.assertRaises(ContractError) as caught_nl:
            machine_records(
                receipt_nl,
                limit=1024,
                code="RPM_INVENTORY_FAILED",
                substage="test-stream",
            )
        self.assertEqual(caught_nl.exception.reason_token, "empty-record")

    def test_machine_records_ordinary_newline_splitting(self):
        receipt = CommandReceipt(["tool"], 0, b"line one  \nline\ttwo\n", b"")
        records = machine_records(
            receipt,
            limit=1024,
            code="RPM_INVENTORY_FAILED",
            substage="test-stream",
        )
        self.assertEqual(records, ["line one  ", "line\ttwo"])

    def test_sanitized_contract_error_fields_and_attached_receipt(self):
        out = b"sample output\n"
        err_bytes = b"stderr note"
        receipt = CommandReceipt(["/usr/bin/rpm", "-qp"], 1, out, err_bytes)
        with self.assertRaises(ContractError) as caught:
            machine_text(
                receipt,
                limit=5,  # Exceeds limit
                code="RPM_INVENTORY_FAILED",
                substage="rpm-preservation-inventory",
            )
        err = caught.exception
        self.assertIs(err.receipt, receipt)
        self.assertEqual(err.stream, "stdout")
        self.assertEqual(err.substage, "rpm-preservation-inventory")
        self.assertEqual(err.tool, "rpm")
        self.assertEqual(err.exit_code, 1)
        self.assertEqual(err.stdout_length, len(out))
        self.assertEqual(err.stderr_length, len(err_bytes))
        self.assertEqual(err.stdout_sha256, digest(out))
        self.assertEqual(err.stderr_sha256, digest(err_bytes))
        self.assertEqual(err.reason_token, "stream-limit-exceeded")
        # Ensure details are sanitized
        self.assertEqual(err.details["reason_token"], "stream-limit-exceeded")
        self.assertEqual(err.details["tool"], "rpm")
        self.assertEqual(err.details["exit_code"], 1)
        self.assertEqual(err.details["stdout_sha256"], digest(out))
        self.assertEqual(err.details["stderr_sha256"], digest(err_bytes))

    def test_exact_16mib_reader_and_plus_one_failure(self):
        # 16384 lines of 1024 bytes each = exact 16 * 1024 * 1024 bytes (16MiB)
        line = b"x" * 1023 + b"\n"
        self.assertEqual(len(line), 1024)
        total_16mib = line * 16384
        self.assertEqual(len(total_16mib), 16 * 1024 * 1024)

        receipt_exact = CommandReceipt(["rpm"], 0, total_16mib, b"")
        records = machine_records(
            receipt_exact,
            limit=16 * 1024 * 1024,
            code="RPM_INVENTORY_FAILED",
            substage="test-16mib",
        )
        self.assertEqual(len(records), 16384)

        # 16MiB + 1 byte
        receipt_plus_one = CommandReceipt(["rpm"], 0, total_16mib + b"x", b"")
        with self.assertRaises(ContractError) as caught:
            machine_records(
                receipt_plus_one,
                limit=16 * 1024 * 1024,
                code="RPM_INVENTORY_FAILED",
                substage="test-16mib",
            )
        self.assertEqual(caught.exception.reason_token, "stream-limit-exceeded")
        self.assertIs(caught.exception.receipt, receipt_plus_one)


class RpmPreservationCollectorIntegrationTests(unittest.TestCase):
    """Integration tests for collect_preservation_inventory with authenticated archive fixture members."""

    def _assert_full_rows(self, inventory, receipts, scratch):
        from tests.rpm_fixtures import fixture_members
        members = fixture_members(scratch)
        rows = {}
        for inode, (path, member) in enumerate(sorted(members.items()), 1):
            row = {key: member[key] for key in ('path', 'type', 'mode', 'size')}
            row.update(owner='root', group='root', inode=inode, device=1, flags=0)
            if member['type'] == 'file': row['sha256'] = member['sha256']
            if member['type'] == 'symlink': row['target'] = member['target']
            rows[path] = row
        self.assertEqual(inventory['files'], rows)
        self.assertEqual(len(inventory['files']), len(members))
        self.assertEqual(set(inventory['files']), set(inventory['expected']))
        for path, expected in inventory['expected'].items():
            for key in ('type', 'mode', 'size', 'sha256', 'target'):
                if key in expected and (key != 'target' or expected['type'] == 'symlink'):
                    self.assertEqual(inventory['files'][path][key], expected[key])
        for receipt, ledger in zip(receipts, inventory['receipts']):
            self.assertEqual(receipt.stdout_sha256, digest(receipt.stdout_bytes))
            self.assertEqual(ledger['stdout_length'], len(receipt.stdout_bytes))
            self.assertEqual(ledger['stdout_sha256'], receipt.stdout_sha256)
            self.assertEqual(len(receipt.stdout_text), min(65536, len(receipt.stdout_bytes)))
            self.assertEqual(ledger['count'], 1 if ledger['query'] == 'algo' else len(rows))

    def _source_hashes(self, ctx, scratch, rpm):
        paths = [rpm, Path(ctx['asset_file']), *sorted((scratch / 'rpmbuild/SOURCES').rglob('*'))]
        return {str(p): digest(p.read_bytes()) for p in paths if p.is_file()}

    def _setup_authenticated_fixture(self, root: Path, member_count: int = 0):
        extra_entries = []
        for i in range(member_count):
            extra_entries.append((f"data/item-{i:05d}.txt", f"content-{i}\n".encode()))

        capture, intent, npm = create_cli_fixture(
            root / "input",
            extra_asset_entries=extra_entries if extra_entries else None,
        )
        ctx = validate_build_inputs(capture, intent, "noarch", adapter="rpm", distro="fedora-43")
        scratch = root / "scratch"
        sources = scratch / "rpmbuild/SOURCES"
        specs = scratch / "rpmbuild/SPECS"
        sources.mkdir(parents=True, exist_ok=True)
        specs.mkdir(parents=True, exist_ok=True)

        name = ctx["project_id"]
        (sources / ctx["asset_name"]).write_bytes(ctx["asset_bytes"])
        staged = scratch / "rpmbuild/staged_node_modules"
        stage_offline_npm_closure(capture, name, npm, staged)
        npm_bundle(staged, sources / "npm-closure.tar.gz")

        cmds = [{"name": "tfsl", "path": "bin/run.js"}, {"name": "tfsl-batch", "path": "bin/batch.js"}]
        spec_text = _render_rpm_spec(
            name,
            ctx["version"],
            1,
            "Fixture",
            "MIT",
            ctx["asset_name"],
            ctx["asset_sha"],
            "noarch",
            ["nodejs >= 22"],
            cmds,
            False,
            "package",
            published_at="2026-09-30T12:00:00Z",
        )
        (specs / f"{name}.spec").write_bytes(spec_text)

        rpm = scratch / "fixture.rpm"
        rpm_bytes = b"controlled-rpm-content-fixture"
        rpm.write_bytes(rpm_bytes)

        return ctx, capture, scratch, staged, cmds, rpm, rpm_bytes

    def test_collector_small_fixture_exact_rows_and_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            ctx, capture, scratch, staged, cmds, rpm, rpm_bytes = self._setup_authenticated_fixture(root, 0)
            runner = MockCommandRunner(
                available_tools={"rpm": "/usr/bin/rpm"},
                handlers={"rpm": lambda argv, cwd=None, env=None: inventory_response(argv, cwd)},
            )
            before = self._source_hashes(ctx, scratch, rpm)
            inventory, receipts = collect_preservation_inventory(
                runner, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                scratch, scratch / "db", scratch / "keys",
            )
            self._assert_full_rows(inventory, receipts, scratch)
            self.assertEqual(before, self._source_hashes(ctx, scratch, rpm))

            # Verification of complete row-set equality and metadata
            self.assertTrue(inventory["complete"])
            self.assertEqual(len(receipts), 3)
            self.assertEqual(inventory["package_sha256"], digest(rpm_bytes))
            self.assertEqual(inventory["asset_sha256"], ctx["asset_sha"])
            self.assertEqual(inventory["payload_manifest_sha256"], ctx["payload"]["payload_manifest_sha256"])

            # Verify both streams are < 64KiB
            dump_rcpt, algo_rcpt, attrs_rcpt = receipts
            self.assertLess(len(dump_rcpt.stdout_bytes), 65536)
            self.assertLess(len(attrs_rcpt.stdout_bytes), 65536)

            # Verify exact full rows including hashes, modes, and metadata
            files = inventory["files"]
            expected = inventory["expected"]
            self.assertEqual(set(files), set(expected))
            for path, row in files.items():
                self.assertIn("mode", row)
                self.assertIn("inode", row)
                self.assertIn("device", row)
                self.assertIn("flags", row)
                if row["type"] == "file":
                    self.assertRegex(row["sha256"], r"^[0-9a-f]{64}$")
                elif row["type"] == "symlink":
                    self.assertIn("target", row)

            # Verify additive receipts ledger on success
            ledger = inventory["receipts"]
            self.assertEqual(len(ledger), 3)
            self.assertEqual([entry["query"] for entry in ledger], ["dump", "algo", "attrs"])
            for entry in ledger:
                self.assertEqual(entry["status"], "pass")
                self.assertEqual(entry["exit_code"], 0)
                self.assertIn("stdout_length", entry)
                self.assertIn("stderr_length", entry)
                self.assertIn("stdout_sha256", entry)
                self.assertIn("stderr_sha256", entry)
                self.assertGreater(entry["count"], 0)

            # Verify inventory diagnostic <= 16KiB
            diag = inventory["inventory_diagnostic"]
            self.assertEqual(diag["schema"], "rs9.rpm-preservation-diagnostic.v1")
            self.assertEqual(diag["status"], "pass")
            diag_raw = json.dumps(diag).encode()
            self.assertLessEqual(len(diag_raw), 16 * 1024)
            self.assertNotIn(b"/usr/", diag_raw)
            self.assertNotIn(str(root).encode(), diag_raw)

    def test_collector_dump_gt_64kib_attrs_lt_64kib(self):
        """Dump stream exceeds 64KiB (CommandReceipt preview truncated), while attrs is under 64KiB."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            # ~550 members produces dump > 64KiB and attrs < 64KiB
            ctx, capture, scratch, staged, cmds, rpm, rpm_bytes = self._setup_authenticated_fixture(root, 550)
            runner = MockCommandRunner(
                available_tools={"rpm": "/usr/bin/rpm"},
                handlers={"rpm": lambda argv, cwd=None, env=None: inventory_response(argv, cwd)},
            )
            before = self._source_hashes(ctx, scratch, rpm)
            inventory, receipts = collect_preservation_inventory(
                runner, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                scratch, scratch / "db", scratch / "keys",
            )
            self._assert_full_rows(inventory, receipts, scratch)
            self.assertEqual(before, self._source_hashes(ctx, scratch, rpm))

            dump_rcpt, _, attrs_rcpt = receipts
            # Verify stream sizes relative to 64KiB preview boundary
            self.assertGreater(len(dump_rcpt.stdout_bytes), 65536)
            self.assertLess(len(attrs_rcpt.stdout_bytes), 65536)

            # Confirm preview is truncated while collector succeeded on full stream
            self.assertLess(len(dump_rcpt.stdout_text), len(dump_rcpt.stdout_bytes))
            self.assertTrue(inventory["complete"])
            self.assertEqual(set(inventory["files"]), set(inventory["expected"]))
            self.assertEqual(len(inventory["files"]), len(inventory["expected"]))

    def test_collector_both_dump_and_attrs_gt_64kib(self):
        """Both dump and attrs streams exceed 64KiB preview boundary."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            # 1200 members produces both dump > 64KiB and attrs > 64KiB
            ctx, capture, scratch, staged, cmds, rpm, rpm_bytes = self._setup_authenticated_fixture(root, 1200)
            runner = MockCommandRunner(
                available_tools={"rpm": "/usr/bin/rpm"},
                handlers={"rpm": lambda argv, cwd=None, env=None: inventory_response(argv, cwd)},
            )
            before = self._source_hashes(ctx, scratch, rpm)
            inventory, receipts = collect_preservation_inventory(
                runner, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                scratch, scratch / "db", scratch / "keys",
            )
            self._assert_full_rows(inventory, receipts, scratch)
            self.assertEqual(before, self._source_hashes(ctx, scratch, rpm))

            dump_rcpt, _, attrs_rcpt = receipts
            self.assertGreater(len(dump_rcpt.stdout_bytes), 65536)
            self.assertGreater(len(attrs_rcpt.stdout_bytes), 65536)

            # Both previews are truncated
            self.assertLess(len(dump_rcpt.stdout_text), len(dump_rcpt.stdout_bytes))
            self.assertLess(len(attrs_rcpt.stdout_text), len(attrs_rcpt.stdout_bytes))

            # Collector succeeds completely
            self.assertTrue(inventory["complete"])
            self.assertEqual(set(inventory["files"]), set(inventory["expected"]))

            # Verify unchanged package, asset, closure, source bytes
            self.assertEqual(inventory["package_sha256"], digest(rpm_bytes))
            self.assertEqual(inventory["asset_sha256"], ctx["asset_sha"])

    def test_collector_errors_past_64kib_boundary(self):
        """Verify errors placed past the 64KiB boundary fail closed with causal receipt and diagnostic."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            ctx, capture, scratch, staged, cmds, rpm, _ = self._setup_authenticated_fixture(root, 1200)

            from rs9.rpm_query import rpm_isolation_args

            def get_clean_receipts():
                runner = MockCommandRunner(
                    available_tools={"rpm": "/usr/bin/rpm"},
                    handlers={"rpm": lambda argv, cwd=None, env=None: inventory_response(argv, cwd)},
                )
                isolation = rpm_isolation_args(dbpath=scratch / "db", keyring="rpmdb", keyringpath=scratch / "keys")
                d = inventory_response(["rpm", *isolation, "-qp", "--dump", str(rpm)], scratch)
                al = inventory_response(["rpm", *isolation, "-qp", "--queryformat", "%{FILEDIGESTALGO}\\n", str(rpm)], scratch)
                at = inventory_response(["rpm", *isolation, "-qp", "--queryformat", "[%{FILENAMES}|%{FILEINODES}|%{FILERDEVS}|%{FILEFLAGS}\\n]", str(rpm)], scratch)
                return d, al, at

            clean_dump, clean_algo, clean_attrs = get_clean_receipts()
            self.assertGreater(len(clean_dump.stdout_bytes), 65536)
            self.assertGreater(len(clean_attrs.stdout_bytes), 65536)

            # 1. Corrupt fields past 64KiB boundary
            dump_text = clean_dump.stdout_bytes.decode()
            idx = dump_text.find("\n", 66000)
            next_nl = dump_text.find("\n", idx + 1)
            corrupt_dump_text = dump_text[:idx + 1] + "malformed record without 11 fields\n" + dump_text[next_nl + 1:]
            bad_dump = CommandReceipt(clean_dump.command, 0, corrupt_dump_text.encode(), b"")

            runner_corrupt = MockCommandRunner(
                available_tools={"rpm": "/usr/bin/rpm"},
                handlers={
                    "rpm": lambda argv, cwd=None, env=None: (
                        bad_dump if "--dump" in argv else inventory_response(argv, cwd)
                    )
                },
            )
            with self.assertRaises(ContractError) as caught:
                collect_preservation_inventory(
                    runner_corrupt, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                    scratch, scratch / "db", scratch / "keys",
                )
            self.assertIs(caught.exception.receipt, bad_dump)
            self.assertEqual(caught.exception.inventory_diagnostic["status"], "fail")

            # 2. Duplicate member past 64KiB boundary
            first_line = dump_text.splitlines()[0]
            dup_dump_text = dump_text[:next_nl + 1] + first_line + "\n" + dump_text[next_nl + 1:]
            dup_dump = CommandReceipt(clean_dump.command, 0, dup_dump_text.encode(), b"")
            runner_dup = MockCommandRunner(
                available_tools={"rpm": "/usr/bin/rpm"},
                handlers={
                    "rpm": lambda argv, cwd=None, env=None: (
                        dup_dump if "--dump" in argv else inventory_response(argv, cwd)
                    )
                },
            )
            with self.assertRaises(ContractError) as caught_dup:
                collect_preservation_inventory(
                    runner_dup, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                    scratch, scratch / "db", scratch / "keys",
                )
            self.assertIs(caught_dup.exception.receipt, dup_dump)

            # 3. Missing attrs past 64KiB boundary (member in dump but missing from attrs)
            attrs_text = clean_attrs.stdout_bytes.decode()
            a_idx = attrs_text.find("\n", 66000)
            a_next = attrs_text.find("\n", a_idx + 1)
            removed_attrs_text = attrs_text[:a_idx + 1] + attrs_text[a_next + 1:]
            bad_attrs = CommandReceipt(clean_attrs.command, 0, removed_attrs_text.encode(), b"")
            runner_missing_attr = MockCommandRunner(
                available_tools={"rpm": "/usr/bin/rpm"},
                handlers={
                    "rpm": lambda argv, cwd=None, env=None: (
                        bad_attrs if "%{FILENAMES}" in (argv[argv.index("--queryformat") + 1] if "--queryformat" in argv else "")
                        else inventory_response(argv, cwd)
                    )
                },
            )
            with self.assertRaises(ContractError) as caught_missing:
                collect_preservation_inventory(
                    runner_missing_attr, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                    scratch, scratch / "db", scratch / "keys",
                )
            # Causal receipt attached is dump (parse_dump unmatched member)
            self.assertIn("--dump", caught_missing.exception.receipt.command)

            # 4. Extra attrs past 64KiB boundary (member in attrs but missing from dump)
            extra_attrs_text = attrs_text[:a_next + 1] + "/usr/lib/extra/file.txt|99999|1|0\n" + attrs_text[a_next + 1:]
            bad_extra_attrs = CommandReceipt(clean_attrs.command, 0, extra_attrs_text.encode(), b"")
            runner_extra_attr = MockCommandRunner(
                available_tools={"rpm": "/usr/bin/rpm"},
                handlers={
                    "rpm": lambda argv, cwd=None, env=None: (
                        bad_extra_attrs if "%{FILENAMES}" in (argv[argv.index("--queryformat") + 1] if "--queryformat" in argv else "")
                        else inventory_response(argv, cwd)
                    )
                },
            )
            with self.assertRaises(ContractError) as caught_extra:
                collect_preservation_inventory(
                    runner_extra_attr, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                    scratch, scratch / "db", scratch / "keys",
                )
            self.assertIn("--dump", caught_extra.exception.receipt.command)

            # 5. Invalid UTF-8 past 64KiB boundary
            raw_dump = clean_dump.stdout_bytes
            corrupt_utf8_dump = CommandReceipt(
                clean_dump.command, 0, raw_dump[:66000] + b"\xff" + raw_dump[66001:], b""
            )
            runner_utf8 = MockCommandRunner(
                available_tools={"rpm": "/usr/bin/rpm"},
                handlers={
                    "rpm": lambda argv, cwd=None, env=None: (
                        corrupt_utf8_dump if "--dump" in argv else inventory_response(argv, cwd)
                    )
                },
            )
            with self.assertRaises(ContractError) as caught_utf8:
                collect_preservation_inventory(
                    runner_utf8, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                    scratch, scratch / "db", scratch / "keys",
                )
            self.assertIs(caught_utf8.exception.receipt, corrupt_utf8_dump)
            self.assertEqual(caught_utf8.exception.reason_token, "stream-decode-failed")

            # 6. Incomplete final line past 64KiB boundary
            truncated_dump = CommandReceipt(clean_dump.command, 0, raw_dump[:70000].rstrip(b"\n"), b"")
            runner_incomp = MockCommandRunner(
                available_tools={"rpm": "/usr/bin/rpm"},
                handlers={
                    "rpm": lambda argv, cwd=None, env=None: (
                        truncated_dump if "--dump" in argv else inventory_response(argv, cwd)
                    )
                },
            )
            with self.assertRaises(ContractError) as caught_incomp:
                collect_preservation_inventory(
                    runner_incomp, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                    scratch, scratch / "db", scratch / "keys",
                )
            self.assertIs(caught_incomp.exception.receipt, truncated_dump)
            self.assertEqual(caught_incomp.exception.reason_token, "incomplete-framing")

            # 7. Empty / trailing bad line past 64KiB boundary
            empty_line_dump = CommandReceipt(
                clean_dump.command, 0, raw_dump[:66000] + b"\n\n" + raw_dump[66000:], b""
            )
            runner_empty = MockCommandRunner(
                available_tools={"rpm": "/usr/bin/rpm"},
                handlers={
                    "rpm": lambda argv, cwd=None, env=None: (
                        empty_line_dump if "--dump" in argv else inventory_response(argv, cwd)
                    )
                },
            )
            with self.assertRaises(ContractError) as caught_empty:
                collect_preservation_inventory(
                    runner_empty, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                    scratch, scratch / "db", scratch / "keys",
                )
            self.assertIs(caught_empty.exception.receipt, empty_line_dump)
            self.assertEqual(caught_empty.exception.reason_token, "empty-record")

            # 8. Non-ASCII numbers (Unicode digit coercion rejection) past 64KiB boundary
            # Replace ASCII digit '0' with Arabic-Indic digit '٠' (U+0660) in size field
            line_target = dump_text[idx + 1:next_nl]
            parts = line_target.split()
            unicode_parts = list(parts)
            unicode_parts[1] = "٠"  # Unicode 0
            bad_num_line = " ".join(unicode_parts)
            bad_num_dump_text = dump_text[:idx + 1] + bad_num_line + "\n" + dump_text[next_nl + 1:]
            bad_num_dump = CommandReceipt(clean_dump.command, 0, bad_num_dump_text.encode(), b"")

            runner_bad_num = MockCommandRunner(
                available_tools={"rpm": "/usr/bin/rpm"},
                handlers={
                    "rpm": lambda argv, cwd=None, env=None: (
                        bad_num_dump if "--dump" in argv else inventory_response(argv, cwd)
                    )
                },
            )
            with self.assertRaises(ContractError) as caught_bad_num:
                collect_preservation_inventory(
                    runner_bad_num, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                    scratch, scratch / "db", scratch / "keys",
                )
            self.assertIs(caught_bad_num.exception.receipt, bad_num_dump)

    def test_collector_oversize_plus_one_failure_without_huge_fixtures(self):
        """Verify collector fails closed on (16MiB + 1) stream without huge fixture archives."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            ctx, capture, scratch, staged, cmds, rpm, _ = self._setup_authenticated_fixture(root, 0)

            oversize_16mib_plus_one = b"x" * (16 * 1024 * 1024 + 1)
            bad_dump = CommandReceipt(["rpm", "-qp", "--dump"], 0, oversize_16mib_plus_one, b"")

            runner = MockCommandRunner(
                available_tools={"rpm": "/usr/bin/rpm"},
                handlers={
                    "rpm": lambda argv, cwd=None, env=None: (
                        bad_dump if "--dump" in argv else inventory_response(argv, cwd)
                    )
                },
            )
            with self.assertRaises(ContractError) as caught:
                collect_preservation_inventory(
                    runner, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                    scratch, scratch / "db", scratch / "keys",
                )
            self.assertEqual(caught.exception.code, "RPM_INVENTORY_FAILED")
            self.assertEqual(caught.exception.reason_token, "stream-limit-exceeded")
            self.assertIs(caught.exception.receipt, bad_dump)
            self.assertEqual(caught.exception.inventory_diagnostic["status"], "fail")
            self.assertLessEqual(len(json.dumps(caught.exception.inventory_diagnostic).encode()), 16 * 1024)

    def test_collector_algo_query_failure_and_bounds(self):
        """Algo query requires exact '8\\n' and 64-byte limit."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            ctx, capture, scratch, staged, cmds, rpm, _ = self._setup_authenticated_fixture(root, 0)

            for bad_algo_bytes, expected_reason in (
                (b"8", "incomplete-framing"),       # Missing trailing newline
                (b"1\n", "algo-mismatch"),          # Wrong algorithm
                (b"8\n\n", "empty-record"),         # Empty record
                (b"x" * 65, "stream-limit-exceeded"), # Exceeds 64-byte limit
                (b"sha256\n", "algo-mismatch"),     # String name instead of exact 8
            ):
                with self.subTest(bad_algo=bad_algo_bytes):
                    bad_algo_rcpt = CommandReceipt(["rpm", "-qp"], 0, bad_algo_bytes, b"")
                    runner = MockCommandRunner(
                        available_tools={"rpm": "/usr/bin/rpm"},
                        handlers={
                            "rpm": lambda argv, cwd=None, env=None, r=bad_algo_rcpt: (
                                r if "%{FILEDIGESTALGO}" in (argv[argv.index("--queryformat") + 1] if "--queryformat" in argv else "")
                                else inventory_response(argv, cwd)
                            )
                        },
                    )
                    with self.assertRaises(ContractError) as caught:
                        collect_preservation_inventory(
                            runner, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                            scratch, scratch / "db", scratch / "keys",
                        )
                    self.assertIs(caught.exception.receipt, bad_algo_rcpt)
                    self.assertEqual(caught.exception.inventory_diagnostic["status"], "fail")

    def test_attribute_late_corruption_and_excessive_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            ctx, capture, scratch, staged, cmds, rpm, _ = self._setup_authenticated_fixture(root, 1200)
            argv = ['rpm', '-qp', '--queryformat', '[%{FILENAMES}|%{FILEINODES}|%{FILERDEVS}|%{FILEFLAGS}\\n]', str(rpm)]
            clean = inventory_response(argv, scratch)
            raw = clean.stdout_bytes
            self.assertGreater(len(raw), 65536)
            first = raw.split(b'\n', 1)[0]
            bad_streams = [raw + b'bad\xff\n', raw[:-1], raw + first + b'\n',
                           raw + b'bad trailing record\n', raw + b'\n',
                           (first + b'\n') * 20001]
            for bad in bad_streams:
                receipt = CommandReceipt(argv, 0, bad, b'')
                runner = MockCommandRunner(available_tools={'rpm':'/usr/bin/rpm'},
                    handlers={'rpm':lambda a, cwd=None, env=None, r=receipt:
                        r if '--queryformat' in a and '%{FILENAMES}' in a[a.index('--queryformat')+1]
                        else inventory_response(a, cwd)})
                with self.subTest(size=len(bad)), self.assertRaises(ContractError) as caught:
                    collect_preservation_inventory(runner, rpm, capture, ctx, staged, cmds,
                        ['nodejs >= 22'], scratch, scratch/'db', scratch/'keys')
                self.assertIs(caught.exception.receipt, receipt)
                ledger = caught.exception.inventory_diagnostic['queries'][-1]
                self.assertEqual(ledger['query'], 'attrs')
                self.assertEqual(ledger['stdout_sha256'], digest(bad))
                self.assertEqual(ledger['stdout_length'], len(bad))
                self.assertEqual(ledger['status'], 'fail')

    def test_query_tool_failure_ledger_keeps_original_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            ctx, capture, scratch, staged, cmds, rpm, _ = self._setup_authenticated_fixture(root)
            receipt = CommandReceipt(['rpm', '--dump'], 7, b'partial query\n', b'query failed\n', executed=True)
            runner = MockCommandRunner(available_tools={'rpm':'/usr/bin/rpm'}, handlers={'rpm':lambda a, **kw:receipt})
            with self.assertRaises(ContractError) as caught:
                collect_preservation_inventory(runner, rpm, capture, ctx, staged, cmds,
                    ['nodejs >= 22'], scratch, scratch/'db', scratch/'keys')
            self.assertIs(caught.exception.receipt, receipt)
            row = caught.exception.inventory_diagnostic['queries'][0]
            self.assertEqual(row['exit_code'], 7)
            self.assertTrue(row['executed'])
            self.assertEqual(row['stdout_sha256'], receipt.stdout_sha256)
            self.assertEqual(row['stderr_sha256'], receipt.stderr_sha256)
            self.assertEqual(row['stdout_length'], len(receipt.stdout_bytes))
            self.assertEqual(row['stderr_length'], len(receipt.stderr_bytes))

    def test_query_stderr_failure_reports_stderr_size_and_receipt(self):
        from rs9.rpm_preservation import _query
        receipt = CommandReceipt(['rpm', '--dump'], 0, b'output\n', b'query diagnostic\n')
        runner = MockCommandRunner(available_tools={'rpm':'/usr/bin/rpm'}, handlers={'rpm':lambda a, **kw:receipt})
        with self.assertRaises(ContractError) as caught:
            _query(runner, Path('fixture.rpm'), Path('.'), [], ['--dump'], 'dump')
        self.assertIs(caught.exception.receipt, receipt)
        self.assertEqual(caught.exception.details['diagnostic_token'], 'stderr')
        self.assertEqual(caught.exception.details['size'], len(receipt.stderr_bytes))
        self.assertEqual(caught.exception.details['reason_token'], 'stderr-not-empty')

    def test_collector_non_query_projection_failures_have_receipt_none(self):
        """Non-query projection failures must set receipt=None and attach diagnostic."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            ctx, capture, scratch, staged, cmds, rpm, _ = self._setup_authenticated_fixture(root, 0)

            # Alter asset_sha to force an authenticated archive identity change
            ctx["asset_sha"] = "0" * 64

            runner = MockCommandRunner(
                available_tools={"rpm": "/usr/bin/rpm"},
                handlers={"rpm": lambda argv, cwd=None, env=None: inventory_response(argv, cwd)},
            )
            with self.assertRaises(ContractError) as caught:
                collect_preservation_inventory(
                    runner, rpm, capture, ctx, staged, cmds, ["nodejs >= 22"],
                    scratch, scratch / "db", scratch / "keys",
                )
            self.assertEqual(caught.exception.code, "INPUT_CHANGED")
            self.assertIsNone(caught.exception.receipt)
            self.assertIsNotNone(caught.exception.inventory_diagnostic)
            self.assertEqual(caught.exception.inventory_diagnostic["status"], "pass")
            self.assertEqual(len(caught.exception.inventory_diagnostic["queries"]), 3)

    def test_parse_dump_strict_canonical_field_checks(self):
        """Direct parse_dump field checks covering octal mode, rdev, digest, and decimal checks."""
        path = "/usr/lib/pkg/test.js"
        valid_digest = digest(b"test")
        valid_line = f"{path} 10 1767225600 {valid_digest} 0100644 root root 0 0 0 X\n"
        valid_attrs = {path: dict(inode=1, device=1, flags=0)}

        # Normal valid parse
        parsed = parse_dump(valid_line, valid_attrs)
        self.assertEqual(parsed[path]["mode"], 0o644)
        self.assertEqual(parsed[path]["sha256"], valid_digest)

        # Non-ASCII digit in size
        with self.assertRaises(ContractError):
            bad_line = f"{path} ۱0 1767225600 {valid_digest} 0100644 root root 0 0 0 X\n"
            parse_dump(bad_line, valid_attrs)

        # Non-ASCII digit in mtime
        with self.assertRaises(ContractError):
            bad_line = f"{path} 10 ۱767225600 {valid_digest} 0100644 root root 0 0 0 X\n"
            parse_dump(bad_line, valid_attrs)

        # Non-octal mode (contains '8')
        with self.assertRaises(ContractError):
            bad_line = f"{path} 10 1767225600 {valid_digest} 0100648 root root 0 0 0 X\n"
            parse_dump(bad_line, valid_attrs)

        # Non-ASCII digit in mode
        with self.assertRaises(ContractError):
            bad_line = f"{path} 10 1767225600 {valid_digest} 010064४ root root 0 0 0 X\n"
            parse_dump(bad_line, valid_attrs)

        # Non-ASCII digit in rdev
        with self.assertRaises(ContractError):
            bad_line = f"{path} 10 1767225600 {valid_digest} 0100644 root root 0 0 ٠ X\n"
            parse_dump(bad_line, valid_attrs)

        # All-zero digest for regular file rejected
        with self.assertRaises(ContractError):
            bad_line = f"{path} 10 1767225600 {'0' * 64} 0100644 root root 0 0 0 X\n"
            parse_dump(bad_line, valid_attrs)

        # Directory with non-zero digest rejected
        dir_path = "/usr/lib/pkg/subdir"
        dir_attrs = {dir_path: dict(inode=2, device=1, flags=0)}
        with self.assertRaises(ContractError):
            bad_dir = f"{dir_path} 4096 1767225600 {valid_digest} 0040755 root root 0 0 0 X\n"
            parse_dump(bad_dir, dir_attrs)

        # Directory with zero digest accepted
        good_dir = f"{dir_path} 4096 1767225600 {'0' * 64} 0040755 root root 0 0 0 X\n"
        dir_parsed = parse_dump(good_dir, dir_attrs)
        self.assertEqual(dir_parsed[dir_path]["type"], "directory")

        # Symlink with non-zero digest rejected
        link_path = "/usr/lib/pkg/link.js"
        link_attrs = {link_path: dict(inode=3, device=1, flags=0)}
        with self.assertRaises(ContractError):
            bad_link = f"{link_path} 7 1767225600 {valid_digest} 0120777 root root 0 0 0 test.js\n"
            parse_dump(bad_link, link_attrs)

        # Symlink with zero digest accepted
        good_link = f"{link_path} 7 1767225600 {'0' * 64} 0120777 root root 0 0 0 test.js\n"
        link_parsed = parse_dump(good_link, link_attrs)
        self.assertEqual(link_parsed[link_path]["type"], "symlink")
        self.assertEqual(link_parsed[link_path]["target"], "test.js")
        # The file-kind field disambiguates a valid symlink named X from the dump placeholder.
        self.assertEqual(parse_dump(good_link.replace('test.js\n', 'X\n'), link_attrs)[link_path]['target'], 'X')

        # Special kind (block or char device) rejected
        with self.assertRaises(ContractError):
            special_line = f"{path} 0 1767225600 {'0' * 64} 0020660 root root 0 0 0 X\n"
            parse_dump(special_line, valid_attrs)


if __name__ == "__main__":
    unittest.main()
