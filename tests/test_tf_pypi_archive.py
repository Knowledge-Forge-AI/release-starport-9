"""Tests for tf_pypi_archive stdlib-only hostile-archive and file reader."""

import gzip
import hashlib
import io
import os
import pathlib
import stat
import tarfile
import tempfile
import unittest

from rs9.tf_pypi_archive import (
    AdmissionError,
    canonical,
    fail,
    physical_bytes,
    read_tar,
    sha256,
)


def make_tar_gz(entries, fmt=tarfile.PAX_FORMAT) -> bytes:
    """Helper to synthesize in-memory tar.gz byte streams."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        with tarfile.open(fileobj=gz, mode="w", format=fmt) as tf:
            for e in entries:
                ti = tarfile.TarInfo(e.get("name", "package/file.txt"))
                ti.mode = e.get("mode", 0o644)
                ti.type = e.get("type", tarfile.REGTYPE)
                if "linkname" in e:
                    ti.linkname = e["linkname"]
                if "pax_headers" in e:
                    ti.pax_headers = e["pax_headers"]
                data = e.get("data", b"")
                ti.size = e.get("size", len(data) if ti.type == tarfile.REGTYPE else 0)
                if ti.type == tarfile.REGTYPE:
                    tf.addfile(ti, io.BytesIO(data))
                else:
                    tf.addfile(ti)
    return buf.getvalue()


class TfPypiArchiveTests(unittest.TestCase):
    def test_public_interface_contracts(self):
        # AdmissionError inheritance and sanitization
        err = AdmissionError("TF_PYPI_ARCHIVE")
        self.assertIsInstance(err, ValueError)
        self.assertEqual(err.code, "TF_PYPI_ARCHIVE")
        self.assertEqual(str(err), "TF_PYPI_ARCHIVE")

        # fail function
        with self.assertRaises(AdmissionError) as ctx:
            fail("ARCHIVE")
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")
        self.assertEqual(str(ctx.exception), "TF_PYPI_ARCHIVE")

        with self.assertRaises(AdmissionError) as ctx2:
            fail("TF_PYPI_PATH")
        self.assertEqual(ctx2.exception.code, "TF_PYPI_PATH")

        # Error sanitization: raw paths stripped
        dirty = AdmissionError("TF_PYPI_PATH: /etc/passwd\n\t")
        self.assertNotIn("/etc/passwd", str(dirty))
        self.assertNotIn("\n", str(dirty))

        # sha256
        data = b"hello starport"
        self.assertEqual(sha256(data), hashlib.sha256(data).hexdigest())

        # canonical JSON sorted compact plus newline
        obj = {"z": 1, "a": [2, 3], "m": {"b": True, "a": False}}
        canon = canonical(obj)
        self.assertTrue(canon.endswith(b"\n"))
        self.assertEqual(canon, b'{"a":[2,3],"m":{"a":false,"b":true},"z":1}\n')

    def test_read_tar_valid_archive(self):
        entries = [
            {"name": "package", "type": tarfile.DIRTYPE, "mode": 0o755},
            {"name": "package/setup.py", "data": b"import setuptools", "mode": 0o644},
            {"name": "package/bin", "type": tarfile.DIRTYPE, "mode": 0o755},
            {"name": "package/bin/run", "data": b"#!/bin/sh\necho hi", "mode": 0o755},
            {"name": "package/src", "type": tarfile.DIRTYPE, "mode": 0o755},
            {"name": "package/src/mod.py", "data": b"x = 42\n", "mode": 0o644},
        ]
        tgz = make_tar_gz(entries)
        result = read_tar(tgz, "package")

        self.assertIn("package/setup.py", result)
        self.assertIn("package/bin/run", result)
        self.assertIn("package/src/mod.py", result)
        self.assertNotIn("package", result)
        self.assertNotIn("package/bin", result)
        self.assertNotIn("package/src", result)

        self.assertEqual(result["package/setup.py"], (b"import setuptools", 0o644))
        self.assertEqual(result["package/bin/run"], (b"#!/bin/sh\necho hi", 0o755))
        self.assertEqual(result["package/src/mod.py"], (b"x = 42\n", 0o644))

        # Custom root
        custom_entries = [
            {"name": "custom_root/a.txt", "data": b"custom", "mode": 0o644},
        ]
        custom_tgz = make_tar_gz(custom_entries)
        custom_res = read_tar(custom_tgz, "custom_root")
        self.assertEqual(custom_res["custom_root/a.txt"], (b"custom", 0o644))

    def test_read_tar_traversal_and_malicious_paths(self):
        bad_paths = [
            "../package/a.py",
            "package/../../etc/passwd",
            "package/sub/../../../etc/shadow",
            "/package/a.py",
            "/etc/passwd",
            "package\\a.py",
            "package/./a.py",
            "./package/a.py",
            "package//a.py",
            "package/\x00a.py",
            "package/\na.py",
            "package/\ra.py",
            "package/\ta.py",
            "package/\x7fa.py",
            "package/e\u0301.py",  # decomposed NFD
            "package/a.py/",  # regular file ending in slash
        ]
        for bad in bad_paths:
            with self.subTest(path=bad):
                tgz = make_tar_gz([{"name": bad, "data": b"bad"}])
                with self.assertRaises(AdmissionError) as ctx:
                    read_tar(tgz)
                self.assertIn(ctx.exception.code, ("TF_PYPI_PATH", "TF_PYPI_ARCHIVE"))

    def test_read_tar_wrong_root(self):
        cases = [
            [{"name": "other_root/a.py", "data": b"content"}],
            [{"name": "a.py", "data": b"content"}],
            [{"name": "package-evil/a.py", "data": b"content"}],
            [{"name": "package", "type": tarfile.REGTYPE, "data": b"root as file"}],
        ]
        for entries in cases:
            with self.subTest(entries=entries):
                tgz = make_tar_gz(entries)
                with self.assertRaises(AdmissionError) as ctx:
                    read_tar(tgz, "package")
                self.assertIn(ctx.exception.code, ("TF_PYPI_ROOT", "TF_PYPI_ARCHIVE", "TF_PYPI_PATH"))

    def test_read_tar_exact_and_casefold_duplicates(self):
        # Exact duplicate files
        tgz = make_tar_gz([
            {"name": "package/a.py", "data": b"v1"},
            {"name": "package/a.py", "data": b"v2"},
        ])
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(tgz)
        self.assertEqual(ctx.exception.code, "TF_PYPI_DUPLICATE")

        # Casefold duplicate files
        tgz = make_tar_gz([
            {"name": "package/a.py", "data": b"v1"},
            {"name": "package/A.py", "data": b"v2"},
        ])
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(tgz)
        self.assertEqual(ctx.exception.code, "TF_PYPI_DUPLICATE")

        # Duplicate directories
        tgz = make_tar_gz([
            {"name": "package/sub", "type": tarfile.DIRTYPE, "mode": 0o755},
            {"name": "package/sub", "type": tarfile.DIRTYPE, "mode": 0o755},
        ])
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(tgz)
        self.assertEqual(ctx.exception.code, "TF_PYPI_DUPLICATE")

        # Casefold duplicate directories
        tgz = make_tar_gz([
            {"name": "package/sub", "type": tarfile.DIRTYPE, "mode": 0o755},
            {"name": "package/SUB", "type": tarfile.DIRTYPE, "mode": 0o755},
        ])
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(tgz)
        self.assertEqual(ctx.exception.code, "TF_PYPI_DUPLICATE")

        # Directory casing collision in segment
        tgz = make_tar_gz([
            {"name": "package/Sub/a.txt", "data": b"1"},
            {"name": "package/sub/b.txt", "data": b"2"},
        ])
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(tgz)
        self.assertEqual(ctx.exception.code, "TF_PYPI_DUPLICATE")

    def test_read_tar_links_and_specials(self):
        specials = [
            {"name": "package/sym", "type": tarfile.SYMTYPE, "linkname": "package/a.py"},
            {"name": "package/hard", "type": tarfile.LNKTYPE, "linkname": "package/a.py"},
            {"name": "package/fifo", "type": tarfile.FIFOTYPE},
            {"name": "package/chr", "type": tarfile.CHRTYPE},
            {"name": "package/blk", "type": tarfile.BLKTYPE},
        ]
        for spec in specials:
            with self.subTest(spec=spec["type"]):
                entries = [{"name": "package/a.py", "data": b"data"}, spec]
                tgz = make_tar_gz(entries)
                with self.assertRaises(AdmissionError) as ctx:
                    read_tar(tgz)
                self.assertEqual(ctx.exception.code, "TF_PYPI_LINK")

    def test_read_tar_file_ancestors(self):
        # File is ancestor of file (file first)
        tgz1 = make_tar_gz([
            {"name": "package/a", "data": b"file"},
            {"name": "package/a/b", "data": b"child"},
        ])
        with self.assertRaises(AdmissionError) as ctx1:
            read_tar(tgz1)
        self.assertEqual(ctx1.exception.code, "TF_PYPI_ANCESTOR")

        # File is ancestor of file (child first)
        tgz2 = make_tar_gz([
            {"name": "package/a/b", "data": b"child"},
            {"name": "package/a", "data": b"file"},
        ])
        with self.assertRaises(AdmissionError) as ctx2:
            read_tar(tgz2)
        self.assertEqual(ctx2.exception.code, "TF_PYPI_ANCESTOR")

        # File is ancestor of directory
        tgz3 = make_tar_gz([
            {"name": "package/a", "data": b"file"},
            {"name": "package/a/b", "type": tarfile.DIRTYPE, "mode": 0o755},
        ])
        with self.assertRaises(AdmissionError) as ctx3:
            read_tar(tgz3)
        self.assertEqual(ctx3.exception.code, "TF_PYPI_ANCESTOR")

        # Directory is ancestor then file tries to occupy directory path
        tgz4 = make_tar_gz([
            {"name": "package/a/b", "type": tarfile.DIRTYPE, "mode": 0o755},
            {"name": "package/a", "data": b"file"},
        ])
        with self.assertRaises(AdmissionError) as ctx4:
            read_tar(tgz4)
        self.assertEqual(ctx4.exception.code, "TF_PYPI_ANCESTOR")

    def test_read_tar_modes(self):
        invalid_modes = [
            (tarfile.REGTYPE, 0o664),
            (tarfile.REGTYPE, 0o777),
            (tarfile.REGTYPE, 0o600),
            (tarfile.REGTYPE, 0o4755),  # setuid
            (tarfile.REGTYPE, 0o2755),  # setgid
            (tarfile.DIRTYPE, 0o700),
            (tarfile.DIRTYPE, 0o775),
            (tarfile.DIRTYPE, 0o777),
            (tarfile.DIRTYPE, 0o644),
        ]
        for type_, mode in invalid_modes:
            with self.subTest(type=type_, mode=oct(mode)):
                name = "package/sub" if type_ == tarfile.DIRTYPE else "package/a.py"
                tgz = make_tar_gz([{"name": name, "type": type_, "mode": mode, "data": b"data"}])
                with self.assertRaises(AdmissionError) as ctx:
                    read_tar(tgz)
                self.assertEqual(ctx.exception.code, "TF_PYPI_MODE")

    def test_read_tar_size_bombs_and_limits(self):
        # Exceed max_members
        entries = [{"name": f"package/f{i}.txt", "data": b"x"} for i in range(10)]
        tgz = make_tar_gz(entries)
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(tgz, max_members=5)
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

        # Exceed max_member_bytes
        single = make_tar_gz([{"name": "package/big.txt", "data": b"x" * 100}])
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(single, max_member_bytes=50)
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

        # Exceed max_total_bytes
        total = make_tar_gz([
            {"name": "package/a.txt", "data": b"x" * 60},
            {"name": "package/b.txt", "data": b"x" * 60},
        ])
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(total, max_total_bytes=100)
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

        # Directory with non-zero size
        dir_bad_size = make_tar_gz([
            {"name": "package/sub", "type": tarfile.DIRTYPE, "mode": 0o755, "size": 10},
        ])
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(dir_bad_size)
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

        # File with negative size header
        neg_buf = io.BytesIO()
        with gzip.GzipFile(fileobj=neg_buf, mode="wb") as gz:
            ti = tarfile.TarInfo("package/a.txt")
            ti.mode = 0o644
            ti.size = 0
            raw = bytearray(ti.tobuf())
            raw[124:136] = b"-000000001\x00 "
            raw[148:156] = b"        "
            chk = sum(raw)
            raw[148:156] = f"{chk:06o}\x00 ".encode()
            gz.write(bytes(raw))
            gz.write(b"\x00" * 1024)
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(neg_buf.getvalue())
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

    def test_read_tar_decompression_ratio_and_header_bombs(self):
        # Gzip bomb: 1 MiB of zeros compressed into small gzip, limit 100 KiB
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            with tarfile.open(fileobj=gz, mode="w") as tf:
                ti = tarfile.TarInfo("package/huge.txt")
                ti.mode = 0o644
                ti.size = 1024 * 1024
                tf.addfile(ti, io.BytesIO(b"\x00" * (1024 * 1024)))
        bomb_data = buf.getvalue()
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(bomb_data, max_total_bytes=100 * 1024)
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

        # Gzip header with oversized filename
        evil_header = bytearray(b"\x1f\x8b\x08\x08\x00\x00\x00\x00\x00\x03")
        evil_header.extend(b"A" * 5000)  # over 4096 bytes header limit
        evil_header.extend(b"\x00")
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(bytes(evil_header))
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

        # Gzip header with unterminated filename
        unterminated = bytes(b"\x1f\x8b\x08\x08\x00\x00\x00\x00\x00\x03" + b"A" * 100)
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(unterminated)
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

    def test_read_tar_truncation_and_malformed(self):
        # Empty input
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(b"")
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

        # Non-gzip input
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(b"PK\x03\x04this-is-zip")
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

        # Truncated gzip
        valid_tgz = make_tar_gz([{"name": "package/a.py", "data": b"hello"}])
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(valid_tgz[:30])
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

        # Truncated tar stream (header says 500 bytes, stream provides 5)
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            ti = tarfile.TarInfo("package/trunc.txt")
            ti.mode = 0o644
            ti.size = 500
            gz.write(ti.tobuf())
            gz.write(b"12345")  # truncated
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(buf.getvalue())
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

        # Corrupted checksum in tar header
        corrupt_buf = io.BytesIO()
        with gzip.GzipFile(fileobj=corrupt_buf, mode="wb") as gz:
            ti = tarfile.TarInfo("package/a.txt")
            ti.mode = 0o644
            ti.size = 0
            raw_hdr = bytearray(ti.tobuf())
            raw_hdr[148:156] = b"999999\x00 "
            gz.write(bytes(raw_hdr))
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(corrupt_buf.getvalue())
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

    def test_read_tar_pax_security(self):
        # Effective PAX traversal
        pax_traversal = make_tar_gz([
            {
                "name": "package/short.txt",
                "pax_headers": {"path": "../../etc/passwd"},
                "data": b"root:x:0:0",
            }
        ])
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(pax_traversal)
        self.assertIn(ctx.exception.code, ("TF_PYPI_PATH", "TF_PYPI_ARCHIVE"))

        # Conflicting PAX and raw paths
        pax_conflict = make_tar_gz([
            {
                "name": "package/a.py",
                "pax_headers": {"path": "package/b.py"},
                "data": b"content",
            }
        ])
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(pax_conflict)
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

        # Raw traversal with safe PAX path
        raw_traversal = make_tar_gz([
            {
                "name": "../../etc/passwd",
                "pax_headers": {"path": "package/safe.txt"},
                "data": b"content",
            }
        ])
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(raw_traversal)
        self.assertIn(ctx.exception.code, ("TF_PYPI_PATH", "TF_PYPI_ARCHIVE"))

        # Legitimate long PAX path (>100 chars)
        long_name = "package/" + "a" * 120 + ".py"
        valid_long_pax = make_tar_gz([
            {"name": long_name, "data": b"long content"},
        ])
        res = read_tar(valid_long_pax)
        self.assertIn(long_name, res)
        self.assertEqual(res[long_name], (b"long content", 0o644))

        # Long PAX path where raw does not match prefix
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
                ti = tarfile.TarInfo("package/" + "x" * 100)
                ti.pax_headers = {"path": "package/" + "y" * 120}
                tf.addfile(ti, io.BytesIO(b"data"))
        with self.assertRaises(AdmissionError) as ctx:
            read_tar(buf.getvalue())
        self.assertEqual(ctx.exception.code, "TF_PYPI_ARCHIVE")

    def test_physical_bytes_valid_and_bounds(self):
        with tempfile.TemporaryDirectory() as td:
            resolved_td = pathlib.Path(td).resolve()
            f = resolved_td / "test.txt"
            f.write_bytes(b"sample physical content")

            # Read valid physical bytes
            b = physical_bytes(f)
            self.assertEqual(b, b"sample physical content")

            # Enforce bound limit
            with self.assertRaises(AdmissionError) as ctx:
                physical_bytes(f, limit=5)
            self.assertEqual(ctx.exception.code, "TF_PYPI_LIMIT")

            # Negative limit
            with self.assertRaises(AdmissionError) as ctx:
                physical_bytes(f, limit=-1)
            self.assertEqual(ctx.exception.code, "TF_PYPI_LIMIT")

            # Non-existent file
            with self.assertRaises((AdmissionError, FileNotFoundError)):
                physical_bytes(resolved_td / "nonexistent.txt")

            # Directory
            with self.assertRaises(AdmissionError) as ctx:
                physical_bytes(resolved_td)
            self.assertEqual(ctx.exception.code, "TF_PYPI_FILE")

    def test_physical_bytes_symlinks_and_mutations(self):
        with tempfile.TemporaryDirectory() as td:
            resolved_td = pathlib.Path(td).resolve()
            real_file = resolved_td / "real.txt"
            real_file.write_bytes(b"real data")

            # Symlink file rejected
            sym = resolved_td / "symlink.txt"
            sym.symlink_to(real_file)
            with self.assertRaises(AdmissionError) as ctx:
                physical_bytes(sym)
            self.assertEqual(ctx.exception.code, "TF_PYPI_SYMLINK")

            # Symlink ancestor rejected
            sub = resolved_td / "subdir"
            sub.mkdir()
            (sub / "inner.txt").write_bytes(b"inner data")
            sub_sym = resolved_td / "sub_sym"
            sub_sym.symlink_to(sub)
            with self.assertRaises(AdmissionError) as ctx:
                physical_bytes(sub_sym / "inner.txt")
            self.assertEqual(ctx.exception.code, "TF_PYPI_SYMLINK")

    def test_no_raw_paths_in_errors(self):
        with tempfile.TemporaryDirectory() as td:
            secret_path = pathlib.Path(td).resolve() / "super_secret_credentials_path.key"
            secret_symlink = pathlib.Path(td).resolve() / "secret_symlink.txt"
            secret_symlink.symlink_to(pathlib.Path(td).resolve())

            # Test missing file error
            try:
                physical_bytes(secret_path)
            except (AdmissionError, FileNotFoundError) as e:
                self.assertNotIn("super_secret_credentials_path", str(e))
                self.assertNotIn(str(secret_path), str(e))

            # Test symlink error
            try:
                physical_bytes(secret_symlink)
            except AdmissionError as e:
                self.assertNotIn("secret_symlink", str(e))
                self.assertNotIn(str(secret_symlink), str(e))

            # Test archive path errors
            archive_bad = make_tar_gz([{"name": "/secret/admin/token.txt", "data": b"token"}])
            try:
                read_tar(archive_bad)
            except AdmissionError as e:
                self.assertNotIn("/secret/admin/token.txt", str(e))


if __name__ == "__main__":
    unittest.main()
