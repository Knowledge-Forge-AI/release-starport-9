"""Unit and regression tests for RPM repository metadata verification and formatting."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest

from rs9.build_native import CommandReceipt
from rs9.errors import ContractError
from rs9.rpm_metadata import verify_repository_metadata
from tests.rpm_metadata_fixtures import create_valid_repodata
from tests.test_repo_apt import FixtureSigner


class RPMRepodataFormatVerifyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.signer = FixtureSigner()
        self.receipt = CommandReceipt(
            ["createrepo_c", "--general-compress-type", "gz", "--no-database", "-s", "sha256", str(self.root)],
            0,
            b"createrepo_c complete\n",
            b"",
            tool_name="createrepo_c",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_coherent_complete_gzip_repository_passes(self):
        create_valid_repodata(self.root, ["Packages/pkg-a-1.0.0-1.fc43.x86_64.rpm"])
        report = verify_repository_metadata(
            self.root,
            expected_packages=["Packages/pkg-a-1.0.0-1.fc43.x86_64.rpm"],
            is_signed=False,
            receipt=self.receipt,
        )
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["operation"], "repodata-format-verify")
        self.assertEqual(report["packages_count"], 1)
        self.assertFalse(report["is_signed"])
        self.assertEqual(report["verified_packages"], ["Packages/pkg-a-1.0.0-1.fc43.x86_64.rpm"])

    def test_direct_builder_layout_arch_rpm_passes(self):
        create_valid_repodata(self.root, ["x86_64/theme-forge-burst-0.6.1-1.fc43.x86_64.rpm"])
        report = verify_repository_metadata(
            self.root,
            expected_packages=["x86_64/theme-forge-burst-0.6.1-1.fc43.x86_64.rpm"],
            is_signed=False,
            receipt=self.receipt,
        )
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["verified_packages"], ["x86_64/theme-forge-burst-0.6.1-1.fc43.x86_64.rpm"])

    def test_empty_repository_passes(self):
        create_valid_repodata(self.root, [])
        report = verify_repository_metadata(
            self.root,
            expected_packages=[],
            is_signed=False,
            receipt=self.receipt,
        )
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["packages_count"], 0)

    def test_malformed_compression_bad_magic(self):
        res = create_valid_repodata(self.root, [])
        primary_href = res["data_files"]["primary"]["href"]
        (self.root / primary_href).write_bytes(b"NOT_A_GZIP_FILE_AT_ALL")
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["operation"], "repodata-format-verify")
        self.assertEqual(caught.exception.details["substage"], "compression-verify")
        self.assertEqual(caught.exception.details["causal_code"], "BAD_COMPRESSION")

    def test_malformed_compression_non_gz_href(self):
        create_valid_repodata(self.root, [])
        repomd = self.root / "repodata/repomd.xml"
        text = repomd.read_text().replace(".xml.gz", ".xml.zst")
        repomd.write_text(text)
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "compression-verify")
        self.assertEqual(caught.exception.details["causal_code"], "BAD_COMPRESSION")

    def test_unsafe_href_rejected(self):
        create_valid_repodata(self.root, [])
        repomd = self.root / "repodata/repomd.xml"
        text = repomd.read_text()
        text = text.replace('href="repodata/', 'href="repodata/../')
        repomd.write_text(text)
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["causal_code"], "UNSAFE_HREF")

    def test_extra_file_in_repodata_fails(self):
        create_valid_repodata(self.root, [])
        extra = self.root / "repodata/extra_rogue.xml.gz"
        extra.write_bytes(b"rogue")
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "repodata-inventory")
        self.assertEqual(caught.exception.details["causal_code"], "UNEXPECTED_OBJECT")
        self.assertEqual(caught.exception.details["target"], "repodata/extra_rogue.xml.gz")

    def test_missing_file_in_repodata_fails(self):
        res = create_valid_repodata(self.root, [])
        other_path = self.root / res["data_files"]["other"]["href"]
        other_path.unlink()
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "repodata-inventory")
        self.assertEqual(caught.exception.details["causal_code"], "MISSING_OBJECT")

    def test_asc_forbidden_before_signing(self):
        create_valid_repodata(self.root, [], is_signed=True, signer=self.signer)
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "repodata-inventory")
        self.assertEqual(caught.exception.details["causal_code"], "UNEXPECTED_SIGNATURE")
        self.assertEqual(caught.exception.details["target"], "repodata/repomd.xml.asc")

    def test_asc_allowed_post_signing(self):
        create_valid_repodata(self.root, [], is_signed=True, signer=self.signer)
        report = verify_repository_metadata(self.root, is_signed=True, receipt=self.receipt)
        self.assertEqual(report["status"], "pass")
        self.assertTrue(report["is_signed"])

    def test_compressed_checksum_mismatch(self):
        res = create_valid_repodata(self.root, [])
        primary_file = self.root / res["data_files"]["primary"]["href"]
        raw = primary_file.read_bytes()
        tampered = bytearray(raw)
        tampered[10] ^= 0xFF
        primary_file.write_bytes(bytes(tampered))
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "checksum-verify")
        self.assertEqual(caught.exception.details["causal_code"], "CHECKSUM_MISMATCH")

    def test_compressed_size_mismatch(self):
        create_valid_repodata(self.root, [])
        repomd = self.root / "repodata/repomd.xml"
        text = repomd.read_text()
        text = text.replace("<size>", "<size>999999", 1)
        repomd.write_text(text)
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "checksum-verify")
        self.assertEqual(caught.exception.details["causal_code"], "SIZE_MISMATCH")

    def test_open_checksum_mismatch(self):
        res = create_valid_repodata(self.root, [])
        repomd = self.root / "repodata/repomd.xml"
        text = repomd.read_text()
        text = text.replace(res["data_files"]["primary"]["open_sha256"], "f" * 64, 1)
        repomd.write_text(text)
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "decompression-verify")
        self.assertEqual(caught.exception.details["causal_code"], "OPEN_CHECKSUM_MISMATCH")

    def test_open_size_mismatch(self):
        create_valid_repodata(self.root, [])
        repomd = self.root / "repodata/repomd.xml"
        text = repomd.read_text()
        text = text.replace("<open-size>", "<open-size>999999", 1)
        repomd.write_text(text)
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "decompression-verify")
        self.assertEqual(caught.exception.details["causal_code"], "OPEN_SIZE_MISMATCH")

    def test_trailing_garbage_fails(self):
        res = create_valid_repodata(self.root, [])
        filelists_file = self.root / res["data_files"]["filelists"]["href"]
        orig = filelists_file.read_bytes()
        filelists_file.write_bytes(orig + b"\x00\x00extra-garbage")
        # Update repomd to match new size and checksum so it passes compressed checks and catches trailing garbage
        repomd = self.root / "repodata/repomd.xml"
        new_sha = hashlib.sha256(filelists_file.read_bytes()).hexdigest()
        new_size = len(filelists_file.read_bytes())
        text = repomd.read_text()
        text = text.replace(res["data_files"]["filelists"]["sha256"], new_sha)
        text = text.replace(f'<size>{res["data_files"]["filelists"]["size"]}</size>', f'<size>{new_size}</size>')
        repomd.write_text(text)
        new_filelists_name = f"{new_sha}-filelists.xml.gz"
        filelists_file.rename(self.root / "repodata" / new_filelists_name)
        text = repomd.read_text()
        text = text.replace(Path(res["data_files"]["filelists"]["href"]).name, new_filelists_name)
        repomd.write_text(text)

        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "decompression-verify")
        self.assertEqual(caught.exception.details["causal_code"], "TRAILING_GARBAGE")

    def test_dtd_forbidden_in_repomd(self):
        create_valid_repodata(self.root, [])
        repomd = self.root / "repodata/repomd.xml"
        repomd.write_bytes(b'<?xml version="1.0"?>\n<!DOCTYPE repomd [\n<!ELEMENT repomd ANY >\n]>\n<repomd/>\n')
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "xml-dtd-forbidden")
        self.assertEqual(caught.exception.details["causal_code"], "DTD_FORBIDDEN")

    def test_entity_forbidden_in_repomd(self):
        create_valid_repodata(self.root, [])
        repomd = self.root / "repodata/repomd.xml"
        repomd.write_bytes(b'<?xml version="1.0"?>\n<!ENTITY test "exploit">\n<repomd/>\n')
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "xml-entity-forbidden")
        self.assertEqual(caught.exception.details["causal_code"], "ENTITY_FORBIDDEN")

    def test_xml_bounds_exceeded(self):
        create_valid_repodata(self.root, [])
        repomd = self.root / "repodata/repomd.xml"
        repomd.write_bytes(b"<repomd>" + b" " * 200 + b"</repomd>")
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt, max_xml_bytes=100)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "xml-bounds")
        self.assertEqual(caught.exception.details["causal_code"], "SIZE_EXCEEDED")

    def test_missing_required_data_type(self):
        create_valid_repodata(self.root, [])
        repomd = self.root / "repodata/repomd.xml"
        text = repomd.read_text()
        # Remove <data type="other">...</data>
        start = text.find('<data type="other">')
        end = text.find('</data>', start) + len('</data>')
        repomd.write_text(text[:start] + text[end:])
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "repomd-parse")
        self.assertEqual(caught.exception.details["causal_code"], "MISSING_DATA_TYPE")

    def test_unexpected_data_type(self):
        create_valid_repodata(self.root, [])
        repomd = self.root / "repodata/repomd.xml"
        text = repomd.read_text()
        text = text.replace('</repomd>', '<data type="primary_db"><location href="repodata/test.xml.gz"/></data></repomd>')
        repomd.write_text(text)
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "repomd-parse")
        self.assertEqual(caught.exception.details["causal_code"], "UNEXPECTED_DATA_TYPE")

    def test_package_count_mismatch_primary(self):
        create_valid_repodata(self.root, ["Packages/pkg-1-1.0.0-1.fc43.x86_64.rpm"])
        # Repackage primary with mismatched count attribute packages="5"
        res = create_valid_repodata(self.root, ["Packages/pkg-1-1.0.0-1.fc43.x86_64.rpm"])
        primary_file = self.root / res["data_files"]["primary"]["href"]
        decomp = gzip.decompress(primary_file.read_bytes()).decode("utf-8")
        decomp = decomp.replace('packages="1"', 'packages="5"')
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            gz.write(decomp.encode("utf-8"))
        comp = buf.getvalue()
        sha = hashlib.sha256(comp).hexdigest()
        open_sha = hashlib.sha256(decomp.encode("utf-8")).hexdigest()
        new_name = f"{sha}-primary.xml.gz"
        primary_file.unlink()
        (self.root / "repodata" / new_name).write_bytes(comp)
        repomd = self.root / "repodata/repomd.xml"
        text = repomd.read_text()
        text = text.replace(Path(res["data_files"]["primary"]["href"]).name, new_name)
        text = text.replace(res["data_files"]["primary"]["sha256"], sha)
        text = text.replace(res["data_files"]["primary"]["open_sha256"], open_sha)
        text = text.replace(f'<size>{res["data_files"]["primary"]["size"]}</size>', f'<size>{len(comp)}</size>')
        text = text.replace(f'<open-size>{res["data_files"]["primary"]["open_size"]}</open-size>', f'<open-size>{len(decomp.encode("utf-8"))}</open-size>')
        repomd.write_text(text)

        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "metadata-linkage")
        self.assertEqual(caught.exception.details["causal_code"], "PACKAGE_COUNT_MISMATCH")

    def test_missing_package_file_on_disk(self):
        create_valid_repodata(self.root, ["Packages/pkg-1-1.0.0-1.fc43.x86_64.rpm"])
        (self.root / "Packages/pkg-1-1.0.0-1.fc43.x86_64.rpm").unlink()
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "package-inventory")
        self.assertEqual(caught.exception.details["causal_code"], "MISSING_PACKAGE")

    def test_package_checksum_mismatch_on_disk(self):
        create_valid_repodata(self.root, ["Packages/pkg-1-1.0.0-1.fc43.x86_64.rpm"])
        target = self.root / "Packages/pkg-1-1.0.0-1.fc43.x86_64.rpm"
        orig = target.read_bytes()
        target.write_bytes(orig[:-1] + b"X")
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "package-inventory")
        self.assertEqual(caught.exception.details["causal_code"], "PACKAGE_CHECKSUM_MISMATCH")

    def test_package_inventory_mismatch_expected(self):
        create_valid_repodata(self.root, ["Packages/pkg-1-1.0.0-1.fc43.x86_64.rpm"])
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(
                self.root,
                expected_packages=["Packages/pkg-DIFFERENT-1.0.0-1.fc43.x86_64.rpm"],
                is_signed=False,
                receipt=self.receipt,
            )
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "package-inventory")
        self.assertEqual(caught.exception.details["causal_code"], "PACKAGE_INVENTORY_MISMATCH")

    def test_dtd_forbidden_in_decompressed_primary(self):
        res = create_valid_repodata(self.root, ["Packages/pkg-1-1.0.0-1.fc43.x86_64.rpm"])
        primary_file = self.root / res["data_files"]["primary"]["href"]
        decomp = gzip.decompress(primary_file.read_bytes()).decode("utf-8")
        decomp = '<?xml version="1.0"?>\n<!DOCTYPE metadata [\n<!ELEMENT metadata ANY >\n]>\n' + decomp
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            gz.write(decomp.encode("utf-8"))
        comp = buf.getvalue()
        sha = hashlib.sha256(comp).hexdigest()
        open_sha = hashlib.sha256(decomp.encode("utf-8")).hexdigest()
        new_name = f"{sha}-primary.xml.gz"
        primary_file.unlink()
        (self.root / "repodata" / new_name).write_bytes(comp)
        repomd = self.root / "repodata/repomd.xml"
        text = repomd.read_text()
        text = text.replace(Path(res["data_files"]["primary"]["href"]).name, new_name)
        text = text.replace(res["data_files"]["primary"]["sha256"], sha)
        text = text.replace(res["data_files"]["primary"]["open_sha256"], open_sha)
        text = text.replace(f'<size>{res["data_files"]["primary"]["size"]}</size>', f'<size>{len(comp)}</size>')
        text = text.replace(f'<open-size>{res["data_files"]["primary"]["open_size"]}</open-size>', f'<open-size>{len(decomp.encode("utf-8"))}</open-size>')
        repomd.write_text(text)

        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "xml-dtd-forbidden")
        self.assertEqual(caught.exception.details["causal_code"], "DTD_FORBIDDEN")

    def test_pkgid_mismatch_filelists(self):
        res = create_valid_repodata(self.root, ["Packages/pkg-1-1.0.0-1.fc43.x86_64.rpm"])
        filelists_file = self.root / res["data_files"]["filelists"]["href"]
        decomp = gzip.decompress(filelists_file.read_bytes()).decode("utf-8")
        decomp = decomp.replace(res["packages"][0]["sha256"], "0" * 64)
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            gz.write(decomp.encode("utf-8"))
        comp = buf.getvalue()
        sha = hashlib.sha256(comp).hexdigest()
        open_sha = hashlib.sha256(decomp.encode("utf-8")).hexdigest()
        new_name = f"{sha}-filelists.xml.gz"
        filelists_file.unlink()
        (self.root / "repodata" / new_name).write_bytes(comp)
        repomd = self.root / "repodata/repomd.xml"
        text = repomd.read_text()
        text = text.replace(Path(res["data_files"]["filelists"]["href"]).name, new_name)
        text = text.replace(res["data_files"]["filelists"]["sha256"], sha)
        text = text.replace(res["data_files"]["filelists"]["open_sha256"], open_sha)
        text = text.replace(f'<size>{res["data_files"]["filelists"]["size"]}</size>', f'<size>{len(comp)}</size>')
        text = text.replace(f'<open-size>{res["data_files"]["filelists"]["open_size"]}</open-size>', f'<open-size>{len(decomp.encode("utf-8"))}</open-size>')
        repomd.write_text(text)

        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "metadata-linkage")
        self.assertEqual(caught.exception.details["causal_code"], "PKGID_MISMATCH")

    def test_metadata_linkage_name_arch_mismatch(self):
        res = create_valid_repodata(self.root, ["Packages/pkg-1-1.0.0-1.fc43.x86_64.rpm"])
        filelists_file = self.root / res["data_files"]["filelists"]["href"]
        decomp = gzip.decompress(filelists_file.read_bytes()).decode("utf-8")
        decomp = decomp.replace('name="pkg-1"', 'name="pkg-mismatched"')
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            gz.write(decomp.encode("utf-8"))
        comp = buf.getvalue()
        sha = hashlib.sha256(comp).hexdigest()
        open_sha = hashlib.sha256(decomp.encode("utf-8")).hexdigest()
        new_name = f"{sha}-filelists.xml.gz"
        filelists_file.unlink()
        (self.root / "repodata" / new_name).write_bytes(comp)
        repomd = self.root / "repodata/repomd.xml"
        text = repomd.read_text()
        text = text.replace(Path(res["data_files"]["filelists"]["href"]).name, new_name)
        text = text.replace(res["data_files"]["filelists"]["sha256"], sha)
        text = text.replace(res["data_files"]["filelists"]["open_sha256"], open_sha)
        text = text.replace(f'<size>{res["data_files"]["filelists"]["size"]}</size>', f'<size>{len(comp)}</size>')
        text = text.replace(f'<open-size>{res["data_files"]["filelists"]["open_size"]}</open-size>', f'<open-size>{len(decomp.encode("utf-8"))}</open-size>')
        repomd.write_text(text)

        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "metadata-linkage")
        self.assertEqual(caught.exception.details["causal_code"], "METADATA_LINKAGE_MISMATCH")

    def test_package_size_mismatch_on_disk(self):
        create_valid_repodata(self.root, ["Packages/pkg-1-1.0.0-1.fc43.x86_64.rpm"])
        target = self.root / "Packages/pkg-1-1.0.0-1.fc43.x86_64.rpm"
        orig = target.read_bytes()
        target.write_bytes(orig + b"EXTRA_BYTES")
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "package-inventory")
        self.assertEqual(caught.exception.details["causal_code"], "PACKAGE_SIZE_MISMATCH")

    def test_symlink_in_repodata_rejected(self):
        create_valid_repodata(self.root, [])
        symlink_target = self.root / "repodata/symlink_obj"
        symlink_target.symlink_to(self.root / "repodata/repomd.xml")
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, is_signed=False, receipt=self.receipt)
        self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
        self.assertEqual(caught.exception.details["substage"], "repodata-inventory")
        self.assertEqual(caught.exception.details["causal_code"], "SYMLINK_REJECTED")

    def test_actual_kit_six_xml_zst_repomd_references_regression(self):
        """Include actual kit six .xml.zst repomd references regression using reference env/path.

        Runs with provided kit by parent and defaults to explicit skip if kit unavailable.
        """
        env_path = os.environ.get("RS9_RUN13_REFERENCE_DIR")
        if not env_path:
            self.skipTest("Run 13 public metadata reference requires RS9_RUN13_REFERENCE_DIR")
        kit_root = Path(env_path)

        tested_repos = 0
        for sys_name in ("candidate-rpm-x86_64-linux", "candidate-rpm-aarch64-linux"):
            arch = "x86_64" if "x86_64" in sys_name else "aarch64"
            repo_path = kit_root / f"evidence/downloaded/{sys_name}/objects/lane-work/rpm/fedora/43/{arch}"
            self.assertTrue((repo_path / "repodata/repomd.xml").is_file())
            import xml.etree.ElementTree as ET
            from rs9.pages import scan_pages_tree
            import shutil
            ns = "http://linux.duke.edu/metadata/repo"
            repomd = ET.fromstring((repo_path / "repodata/repomd.xml").read_bytes())
            nodes = repomd.findall(f"{{{ns}}}data")
            self.assertEqual({n.get("type") for n in nodes}, {"primary", "filelists", "other"})
            for node in nodes:
                href = node.find(f"{{{ns}}}location").get("href")
                raw = (repo_path / href).read_bytes()
                self.assertTrue(href.endswith(".xml.zst"))
                self.assertEqual(raw[:4], bytes.fromhex("28b52ffd"))
                self.assertEqual(hashlib.sha256(raw).hexdigest(), node.find(f"{{{ns}}}checksum").text)
                self.assertEqual(len(raw), int(node.find(f"{{{ns}}}size").text))
            public = self.root / ("pages-" + arch)
            target = public / f"rpm/fedora/43/{arch}/repodata"
            shutil.copytree(repo_path / "repodata", target)
            with self.assertRaises(ContractError) as rejected:
                scan_pages_tree(public)
            self.assertEqual(rejected.exception.code, "DISALLOWED_FILE")
            self.assertEqual(rejected.exception.details["substage"], "pages-path-classification")
            self.assertTrue(rejected.exception.details["path"].endswith(".xml.zst"))

            tested_repos += 1
            with self.assertRaises(ContractError) as caught:
                verify_repository_metadata(repo_path, is_signed=True)
            self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
            self.assertEqual(caught.exception.details["operation"], "repodata-format-verify")
            self.assertEqual(caught.exception.details["substage"], "compression-verify")
            self.assertEqual(caught.exception.details["causal_code"], "BAD_COMPRESSION")
            self.assertTrue(caught.exception.details["target"].endswith(".xml.zst"))

        self.assertEqual(tested_repos, 2)

    def test_complete_gzip_repository_matches_pages_paths(self):
        from rs9.pages import scan_pages_tree
        candidate = self.root / "rpm/fedora/43/x86_64"
        create_valid_repodata(candidate, [])
        self.assertEqual(verify_repository_metadata(candidate, expected_packages=[])["status"], "pass")
        scan_pages_tree(self.root)

    def test_fixed_decompression_limit_is_not_raised_by_open_size(self):
        create_valid_repodata(self.root, [])
        repomd = self.root / "repodata/repomd.xml"
        repomd.write_text(repomd.read_text().replace("<open-size>", "<open-size>999999"))
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, max_decompressed_bytes=100)
        self.assertEqual(caught.exception.details["causal_code"], "SIZE_EXCEEDED")

    def test_duplicate_checksum_and_extra_physical_package_are_rejected(self):
        create_valid_repodata(self.root, [])
        repomd = self.root / "repodata/repomd.xml"
        text = repomd.read_text()
        first = text[text.index('<checksum'):text.index('</checksum>') + len('</checksum>')]
        repomd.write_text(text.replace(first, first + first, 1))
        with self.assertRaises(ContractError):
            verify_repository_metadata(self.root)
        create_valid_repodata(self.root, [])
        packages = self.root / "Packages"; packages.mkdir()
        (packages / "unlisted-1-1.noarch.rpm").write_bytes(b"unlisted")
        with self.assertRaises(ContractError) as caught:
            verify_repository_metadata(self.root, expected_packages=[])
        self.assertEqual(caught.exception.details["causal_code"], "PACKAGE_INVENTORY_MISMATCH")


if __name__ == "__main__":
    unittest.main(verbosity=2)
