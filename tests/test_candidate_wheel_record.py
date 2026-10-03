"""Duplicate wheel members/RECORD rows cannot satisfy bidirectional inspection."""
import csv
import io
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile

from rs9.errors import ContractError
from rs9.verify_wheel import verify_wheel_record_bidirectional
from rs9.wheel import _record_digest, inspect_wheel, verify_wheel_record


class CandidateWheelRecordTests(unittest.TestCase):
    def check_duplicate(self, duplicate_member=False):
        metadata = b"Metadata-Version: 2.4\nName: fixture\nVersion: 1.0.0\n"
        name, record = "fixture.dist-info/METADATA", "fixture.dist-info/RECORD"
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow([name, _record_digest(metadata), len(metadata)])
        if not duplicate_member:
            writer.writerow([name, _record_digest(metadata), len(metadata)])
        writer.writerow([record, "", ""])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.whl"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(name, metadata)
                    if duplicate_member:
                        archive.writestr(name, metadata)
                    archive.writestr(record, buffer.getvalue())

            # 1. verify_wheel_record_bidirectional rejects with RECORD_MISMATCH
            with self.assertRaises(ContractError) as caught_bidi:
                verify_wheel_record_bidirectional(path)
            self.assertEqual(caught_bidi.exception.code, "RECORD_MISMATCH")

            # 2. verify_wheel_record rejects with RECORD_MISMATCH
            with self.assertRaises(ContractError) as caught_rec:
                verify_wheel_record(path)
            self.assertEqual(caught_rec.exception.code, "RECORD_MISMATCH")

            # 3. inspect_wheel flags record_valid as False
            inv = inspect_wheel(path)
            self.assertFalse(inv["record_valid"])

    def test_duplicate_zip_member_rejected(self):
        self.check_duplicate(duplicate_member=True)

    def test_duplicate_record_row_rejected(self):
        self.check_duplicate()

    def test_unlisted_zip_member_rejected(self):
        metadata = b"Metadata-Version: 2.4\nName: fixture\nVersion: 1.0.0\n"
        name, record = "fixture.dist-info/METADATA", "fixture.dist-info/RECORD"
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow([name, _record_digest(metadata), len(metadata)])
        writer.writerow([record, "", ""])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.whl"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(name, metadata)
                archive.writestr("fixture/unlisted.py", b"print('unlisted')\n")
                archive.writestr(record, buffer.getvalue())

            with self.assertRaises(ContractError) as caught_bidi:
                verify_wheel_record_bidirectional(path)
            self.assertEqual(caught_bidi.exception.code, "RECORD_MISMATCH")

            with self.assertRaises(ContractError) as caught_rec:
                verify_wheel_record(path)
            self.assertEqual(caught_rec.exception.code, "RECORD_MISMATCH")

            self.assertFalse(inspect_wheel(path)["record_valid"])

    def test_missing_zip_member_in_record_rejected(self):
        metadata = b"Metadata-Version: 2.4\nName: fixture\nVersion: 1.0.0\n"
        name, record = "fixture.dist-info/METADATA", "fixture.dist-info/RECORD"
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow([name, _record_digest(metadata), len(metadata)])
        writer.writerow(["fixture/missing.py", "sha256=xxx", 123])
        writer.writerow([record, "", ""])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.whl"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(name, metadata)
                archive.writestr(record, buffer.getvalue())

            with self.assertRaises(ContractError) as caught_bidi:
                verify_wheel_record_bidirectional(path)
            self.assertEqual(caught_bidi.exception.code, "RECORD_MISMATCH")

            with self.assertRaises(ContractError) as caught_rec:
                verify_wheel_record(path)
            self.assertEqual(caught_rec.exception.code, "RECORD_MISMATCH")

            self.assertFalse(inspect_wheel(path)["record_valid"])

    def test_hash_or_size_invalid_record_rejected(self):
        metadata = b"Metadata-Version: 2.4\nName: fixture\nVersion: 1.0.0\n"
        extra = b"data\n"
        name, record = "fixture.dist-info/METADATA", "fixture.dist-info/RECORD"
        extra_name = "fixture/extra.py"

        # Digest mismatch
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow([name, _record_digest(metadata), len(metadata)])
        writer.writerow([extra_name, "sha256=invalid_digest", len(extra)])
        writer.writerow([record, "", ""])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.whl"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(name, metadata)
                archive.writestr(extra_name, extra)
                archive.writestr(record, buffer.getvalue())

            with self.assertRaises(ContractError) as caught:
                verify_wheel_record_bidirectional(path)
            self.assertEqual(caught.exception.code, "RECORD_MISMATCH")
            with self.assertRaises(ContractError) as caught_rec:
                verify_wheel_record(path)
            self.assertEqual(caught_rec.exception.code, "RECORD_MISMATCH")
            self.assertFalse(inspect_wheel(path)["record_valid"])

        # Size mismatch
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow([name, _record_digest(metadata), len(metadata)])
        writer.writerow([extra_name, _record_digest(extra), len(extra) + 99])
        writer.writerow([record, "", ""])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture2.whl"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr(name, metadata)
                archive.writestr(extra_name, extra)
                archive.writestr(record, buffer.getvalue())

            with self.assertRaises(ContractError) as caught:
                verify_wheel_record_bidirectional(path)
            self.assertEqual(caught.exception.code, "RECORD_MISMATCH")
            with self.assertRaises(ContractError) as caught_rec:
                verify_wheel_record(path)
            self.assertEqual(caught_rec.exception.code, "RECORD_MISMATCH")
            self.assertFalse(inspect_wheel(path)["record_valid"])
