"""Complete-stream integrity and malformed runtime metadata regressions."""
import gzip
import io
import tarfile
import unittest

from rs9.tf_pypi_archive import AdmissionError, read_tar
from rs9.tf_pypi_backend import build_pair, write_tar
from rs9.tf_pypi_model import admit_bytes
from tests.tf_pypi_fixtures import fixture


class CustodyTests(unittest.TestCase):
    def test_gzip_trailer_and_trailing_payload_are_not_ignored(self):
        _, data = fixture()
        bad_crc = data[:-8] + bytes([data[-8] ^ 1]) + data[-7:]
        for body in (data[:-8], bad_crc, data + b"trailing-payload",
                     data + gzip.compress(b"hidden second stream"), data + gzip.compress(b"")):
            with self.subTest(case=len(body)), self.assertRaises(AdmissionError):
                read_tar(body)

    def test_hidden_tar_members_after_end_markers_refused(self):
        _, data = fixture()
        second = write_tar({"hidden": (b"payload", 0o644)}, "package")
        with self.assertRaises(AdmissionError):
            read_tar(gzip.compress(gzip.decompress(data) + gzip.decompress(second)))

    def test_non_ascii_and_windows_path_aliases_refused(self):
        for path in ("data/\u00e9.txt", "C:alias", "data/a:stream"):
            with self.subTest(path=path), self.assertRaises(AdmissionError):
                read_tar(write_tar({path: (b"data", 0o644)}, "package"))

    def test_malformed_node_engine_is_a_sanitized_contract_error(self):
        for engines in (None, ">=22", [], 22):
            pin, data = fixture(changes={"engines": engines})
            with self.subTest(engines=engines), self.assertRaises(AdmissionError) as caught:
                admit_bytes(pin, data, pin["asset"])
            self.assertEqual(caught.exception.code, "TF_PYPI_NODE_ENGINE")

    def test_native_architecture_slots_cannot_bypass_universal_refusal(self):
        import struct
        import tempfile
        from pathlib import Path
        for slot, arch in (("linux-arm64-gnu", 62), ("linux-x64-gnu", 183)):
            header = bytearray(64)
            header[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<HH", header, 16, 3, arch)
            pin, data = fixture(extra={f"native/prebuilds/{slot}/addon.node": (bytes(header), 0o644)})
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(AdmissionError) as caught:
                build_pair(pin, data, Path(directory).resolve() / "dist")
            self.assertEqual(caught.exception.code, "TF_PYPI_NATIVE_UNQUALIFIED")
