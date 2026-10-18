"""Synthetic wheel/sdist installability, custody and isolated PEP 517 backend."""
import csv
import io
import os
from pathlib import Path
import subprocess
import sys
import struct
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from unittest.mock import patch

from rs9.tf_pypi_archive import AdmissionError, read_tar
from rs9.tf_pypi_backend import (build_pair, metadata, names, project_toml, sdist_entries,
                                wheel_entries, write_tar, write_zip)
from rs9.tf_pypi_verify import read_wheel, verify_manifest, verify_pair, verify_record
from tests.tf_pypi_fixtures import fixture


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.pin, self.data = fixture()

    def test_double_build_offline_deterministic_and_manifest_binding(self):
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            for name in ("one", "two"):
                build_pair(self.pin, self.data, self.root / name)
                verify_pair(self.pin, self.root / name)
        one, two = self.root / "one", self.root / "two"
        self.assertEqual({p.name: p.read_bytes() for p in one.iterdir()},
                         {p.name: p.read_bytes() for p in two.iterdir()})
        manifest = verify_pair(self.pin, one)
        self.assertFalse(manifest["publication_admitted"])
        verify_manifest(self.pin, one, manifest)
        manifest["set_sha256"] = "0" * 64
        with self.assertRaises(AdmissionError):
            verify_manifest(self.pin, one, manifest)

    def test_legal_paths_metadata_payload_modes_and_entrypoints(self):
        import email.parser
        import tomllib
        wheel, sdist = wheel_entries(self.pin, self.data), sdist_entries(self.pin, self.data)
        _, _, info = names(self.pin)
        meta = email.parser.BytesParser().parsebytes(wheel[info + "/METADATA"][0])
        self.assertEqual(meta["Name"], self.pin["project"])
        self.assertEqual(meta["Requires-Python"], ">=3.9")
        self.assertEqual(meta["Requires-External"], "nodejs (>=22)")
        self.assertEqual(meta["License-Expression"], "AGPL-3.0-or-later")
        self.assertEqual(wheel[info + "/METADATA"], sdist["PKG-INFO"])
        for name in meta.get_all("License-File"):
            self.assertEqual(wheel[info + "/licenses/" + name], sdist[name])
        config = tomllib.loads(sdist["pyproject.toml"][0].decode())
        self.assertEqual(config["project"]["name"], meta["Name"])
        self.assertEqual(config["project"]["version"], meta["Version"])
        self.assertEqual(config["project"]["license-files"], meta.get_all("License-File"))
        self.assertEqual(config["project"]["description"], meta["Summary"])
        self.assertEqual(config["project"]["requires-python"], meta["Requires-Python"])
        self.assertEqual(config["project"]["license"], meta["License-Expression"])
        self.assertEqual(config["project"]["classifiers"], meta.get_all("Classifier"))
        self.assertEqual(config["project"]["urls"],
                         dict(line.split(", ", 1) for line in meta.get_all("Project-URL")))
        self.assertEqual(config["project"]["readme"],
                         {"file": "README.md", "content-type": meta["Description-Content-Type"]})
        self.assertEqual(sdist["README.md"][0].decode(), meta.get_payload())
        self.assertEqual(config["project"]["dynamic"], [])
        scripts = dict(line.split(" = ", 1) for line in
                       wheel[info + "/entry_points.txt"][0].decode().splitlines()[1:])
        self.assertEqual(config["project"]["scripts"], scripts)
        notice = sdist["RS9-NOTICE"][0]
        self.assertIn(b"Copyright (c) 2026 Samuel Leighton Lair", notice)
        self.assertIn(b"GNU Affero General Public License", notice)
        self.assertIn("RS9-NOTICE", meta.get_all("License-File"))
        self.assertEqual(config["build-system"]["requires"], [])
        files = read_tar(self.data)
        for path, value in files.items():
            self.assertEqual(wheel[names(self.pin)[0] + "/payload/" + path], value)

    def test_record_tamper_surplus_duplicate_and_missing_are_rejected(self):
        files = wheel_entries(self.pin, self.data)
        info = names(self.pin)[2]
        for mutation in ("content", "extra", "duplicate", "missing"):
            bad = dict(files)
            if mutation == "content":
                bad[info + "/METADATA"] = (b"bad", 0o644)
            elif mutation == "extra":
                bad["extra.txt"] = (b"extra", 0o644)
            elif mutation == "missing":
                bad.pop(info + "/WHEEL")
            else:
                record = bad[info + "/RECORD"][0]
                bad[info + "/RECORD"] = (record + record.splitlines(keepends=True)[0], 0o644)
            with self.subTest(mutation=mutation), self.assertRaises(AdmissionError):
                verify_record(bad, info)

    def test_zip_paths_symlink_duplicate_and_casefold_rejected(self):
        import stat
        import warnings
        import zipfile
        for paths, mode in ((["../bad"], stat.S_IFREG | 0o644), (["/bad"], stat.S_IFREG | 0o644),
                            (["a", "a"], stat.S_IFREG | 0o644), (["a", "A"], stat.S_IFREG | 0o644),
                            (["a"], stat.S_IFLNK | 0o777), (["a", "a/b"], stat.S_IFREG | 0o644)):
            output = io.BytesIO()
            with warnings.catch_warnings(), zipfile.ZipFile(output, "w") as archive:
                warnings.simplefilter("ignore", UserWarning)
                for path in paths:
                    entry = zipfile.ZipInfo(path)
                    entry.external_attr = mode << 16
                    archive.writestr(entry, b"x")
            with self.subTest(paths=paths), self.assertRaises(AdmissionError):
                read_wheel(output.getvalue())

    def test_forged_zip_size_cannot_trigger_unbounded_decompression(self):
        output = io.BytesIO()
        member = zipfile.ZipInfo("payload")
        member.external_attr = 0o100644 << 16
        member.compress_type = zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr(member, b"x" * (9 * 1024**2))
        data = bytearray(output.getvalue())
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<L", data, 22, 1)
        struct.pack_into("<L", data, central + 24, 1)
        decompress = zlib.decompressobj
        observed = []

        class Decoder:
            def __init__(self, *args, **kwargs):
                self.actual = decompress(*args, **kwargs)
            def __getattr__(self, name):
                return getattr(self.actual, name)
            def decompress(self, body, maximum=0):
                result = self.actual.decompress(body, maximum)
                observed.append(len(result))
                return result

        with patch("zipfile.zlib.decompressobj", Decoder), self.assertRaises(AdmissionError) as caught:
            read_wheel(bytes(data))
        self.assertEqual(caught.exception.code, "TF_PYPI_WHEEL")
        self.assertTrue(observed)
        self.assertLessEqual(max(observed), 8 * 1024**2 + 1)
        # Other ZIP codecs do not all honor a bounded decompression request.
        for compression in (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            output = io.BytesIO()
            member.compress_type = compression
            with zipfile.ZipFile(output, "w") as archive:
                archive.writestr(member, b"safe")
            with self.subTest(compression=compression), self.assertRaises(AdmissionError):
                read_wheel(output.getvalue())

    def test_pair_rejects_metadata_tag_payload_sdist_and_file_set_tamper(self):
        for mutation in ("metadata", "tag", "sdist", "extra", "missing"):
            output = self.root / mutation
            build_pair(self.pin, self.data, output)
            if mutation in {"metadata", "tag"}:
                files = wheel_entries(self.pin, self.data)
                target = names(self.pin)[2] + ("/METADATA" if mutation == "metadata" else "/WHEEL")
                files[target] = (b"mutated", 0o644)
                (output / (names(self.pin)[1] + "-py3-none-macosx_11_0_arm64.whl")).write_bytes(write_zip(files))
            elif mutation == "sdist":
                files = sdist_entries(self.pin, self.data)
                files["PKG-INFO"] = (b"mutated", 0o644)
                (output / (names(self.pin)[1] + ".tar.gz")).write_bytes(write_tar(files, names(self.pin)[1]))
            elif mutation == "extra":
                (output / "extra.whl").touch()
            else:
                next(output.glob("*.whl")).unlink()
            with self.subTest(mutation=mutation), self.assertRaises(AdmissionError):
                verify_pair(self.pin, output)

    def test_burst_never_emits_a_universal_or_partial_package(self):
        pin, data = fixture("theme-forge-stellar-burst")
        with self.assertRaises(AdmissionError) as caught:
            build_pair(pin, data, self.root / "burst")
        self.assertEqual(caught.exception.code, "TF_PYPI_NATIVE_UNQUALIFIED")
        self.assertFalse((self.root / "burst").exists())

    def test_forged_valid_record_cannot_relabel_tag_or_entrypoints(self):
        import base64
        import hashlib
        for member in ("WHEEL", "entry_points.txt", "METADATA"):
            output = self.root / ("forged-" + member)
            build_pair(self.pin, self.data, output)
            files = wheel_entries(self.pin, self.data)
            info = names(self.pin)[2]
            files[info + "/" + member] = (b"Tag: py3-none-linux_aarch64\n", 0o644)
            record = io.StringIO(newline="")
            writer = csv.writer(record, lineterminator="\n")
            for path, (body, _) in sorted(files.items()):
                if path != info + "/RECORD":
                    digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip("=")
                    writer.writerow([path, "sha256=" + digest, len(body)])
            writer.writerow([info + "/RECORD", "", ""])
            files[info + "/RECORD"] = (record.getvalue().encode(), 0o644)
            verify_record(files, info)
            next(output.glob("*.whl")).write_bytes(write_zip(files))
            with self.subTest(member=member), self.assertRaises(AdmissionError) as caught:
                verify_pair(self.pin, output)
            self.assertEqual(caught.exception.code, "TF_PYPI_METADATA" if member == "METADATA" else "TF_PYPI_WHEEL_MATCH")

    def test_self_contained_sdist_backend_rebuilds_in_clean_process_offline(self):
        build_pair(self.pin, self.data, self.root / "dist")
        source = self.root / "source"
        source.mkdir()
        # Only test-generated, admitted files are materialized. No untrusted extractall.
        for name, (body, mode) in sdist_entries(self.pin, self.data).items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(mode)
        script = ("import sys,socket;from pathlib import Path;sys.path.insert(0,str(Path.cwd()/'_rs9_build'));"
                  "socket.socket=lambda *a,**k:(_ for _ in ()).throw(AssertionError('network'));"
                  "from rs9 import tf_pypi_backend as b;"
                  "assert b.get_requires_for_build_wheel()==[];b.build_wheel('rebuilt')")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", script], cwd=source,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(next((source / "rebuilt").glob("*.whl")).read_bytes(),
                         next((self.root / "dist").glob("*.whl")).read_bytes())

    def test_backend_import_through_directory_alias_preserves_offline_rebuild(self):
        source = self.root / "source"
        for name, (body, mode) in sdist_entries(self.pin, self.data).items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(mode)
        alias = self.root / "alias"
        alias.symlink_to(source, target_is_directory=True)
        script = ("import sys,socket;sys.path.insert(0,sys.argv[1]);"
                  "socket.socket=lambda *a,**k:(_ for _ in ()).throw(AssertionError('network'));"
                  "from rs9 import tf_pypi_backend as b;"
                  "assert 'alias' in b.__file__;"
                  "assert b.get_requires_for_build_wheel()==[];b.build_wheel('rebuilt')")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(alias / "_rs9_build")],
                                cwd=source, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(next((source / "rebuilt").glob("*.whl")).read_bytes(),
                         write_zip(wheel_entries(self.pin, self.data)))

    def test_sdist_backend_refuses_changed_static_project_metadata(self):
        source = self.root / "source"
        for name, (body, mode) in sdist_entries(self.pin, self.data).items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(mode)
        script = ("import sys;sys.path.insert(0,'_rs9_build');"
                  "from rs9 import tf_pypi_backend as b;b.build_wheel('rebuilt')")
        for name, replacement in (("pyproject.toml", b'[project]\nname = "changed"\n'),
                                  ("README.md", b"Changed static description\n")):
            path = source / name
            original = path.read_bytes()
            path.write_bytes(replacement)
            with self.subTest(name=name):
                result = subprocess.run([sys.executable, "-I", "-B", "-c", script], cwd=source,
                                        capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"TF_PYPI_BUILD_METADATA", result.stderr)
            path.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
