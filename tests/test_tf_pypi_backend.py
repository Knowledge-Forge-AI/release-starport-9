"""Synthetic wheel/sdist installability, custody and isolated PEP 517 backend."""
import base64
import copy
import csv
import email.parser
import hashlib
import io
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch
import warnings
import zipfile
import zlib

from rs9.tf_pypi_archive import AdmissionError, physical_bytes, read_tar
from rs9.tf_pypi_backend import (
    build_aggregate,
    build_pair,
    description,
    description_bytes,
    description_name,
    metadata,
    names,
    project_toml,
    project_urls,
    sdist_entries,
    wheel_entries,
    write_tar,
    write_zip,
)
from rs9.tf_pypi_model import PRODUCTS, TARGETS, load_pin
from rs9.tf_pypi_platform import host_key
from rs9.tf_pypi_verify import (
    host_view,
    read_wheel,
    verify_aggregate,
    verify_manifest,
    verify_pair,
    verify_record,
)
from tests.tf_pypi_fixtures import ROOT, aggregate, fixture, qualified


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.pin, self.data = fixture()

    def test_double_build_offline_deterministic_and_manifest_binding(self):
        with patch("socket.socket", side_effect=AssertionError("network attempted")):
            for name in ("one", "two"):
                build_pair(self.pin, self.data, self.root / name, target="darwin-arm64")
                verify_pair(self.pin, self.root / name, target="darwin-arm64")
        one, two = self.root / "one", self.root / "two"
        self.assertEqual({p.name: p.read_bytes() for p in one.iterdir()},
                         {p.name: p.read_bytes() for p in two.iterdir()})
        manifest = verify_pair(self.pin, one, target="darwin-arm64")
        self.assertEqual(manifest["version"], self.pin["distribution_version"])
        self.assertEqual(manifest["upstream_version"], self.pin["version"])
        self.assertFalse(manifest["publication_admitted"])
        with patch("rs9.tf_pypi_platform.host_key", return_value="darwin-arm64"):
            verify_manifest(self.pin, one, manifest)
            manifest["set_sha256"] = "0" * 64
            with self.assertRaises(AdmissionError):
                verify_manifest(self.pin, one, manifest)

    def test_post1_identity_and_upstream_release_url_separation(self):
        package, stem, info = names(self.pin)
        self.assertEqual(package, "theme_forge_stellar_loom")
        self.assertEqual(stem, "theme_forge_stellar_loom-0.4.0.post1")
        self.assertEqual(info, "theme_forge_stellar_loom-0.4.0.post1.dist-info")
        urls = project_urls(self.pin)
        self.assertTrue(urls["Release"].endswith("/releases/tag/v0.4.0"))
        self.assertNotIn("post1", urls["Release"])

    def test_legal_paths_metadata_payload_modes_and_entrypoints(self):
        wheel = wheel_entries(self.pin, self.data, target="darwin-arm64")
        sdist = sdist_entries(self.pin, self.data, target="darwin-arm64")
        _, _, info = names(self.pin)
        meta = email.parser.BytesParser().parsebytes(wheel[info + "/METADATA"][0])
        self.assertEqual(meta["Name"], self.pin["project"])
        self.assertEqual(meta["Version"], self.pin["distribution_version"])
        self.assertEqual(meta["Requires-Python"], ">=3.9")
        self.assertEqual(meta["Requires-External"], "nodejs (>=22)")
        self.assertEqual(meta["License-Expression"], "AGPL-3.0-or-later")
        self.assertEqual(wheel[info + "/METADATA"], sdist["PKG-INFO"])
        for name in meta.get_all("License-File"):
            self.assertEqual(wheel[info + "/licenses/" + name], sdist[name])
        config = tomllib.loads(sdist["pyproject.toml"][0].decode())
        self.assertEqual(config["project"]["name"], meta["Name"])
        self.assertEqual(config["project"]["version"], self.pin["distribution_version"])
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
        source_desc = physical_bytes(ROOT / "operators/tf-pypi/descriptions" / description_name(self.pin))
        self.assertEqual(sdist["README.md"][0], source_desc)
        self.assertEqual(sdist["_rs9_build/rs9/descriptions/" + description_name(self.pin)][0], source_desc)
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

    def test_descriptions_cover_all_products_and_forbid_draft_tokens(self):
        for project in PRODUCTS:
            pin = load_pin(project)
            text = description(pin)
            raw = description_bytes(pin)
            self.assertGreaterEqual(len(raw), 512)
            self.assertLessEqual(len(raw), 65536)
            self.assertEqual(raw, physical_bytes(ROOT / "operators/tf-pypi/descriptions" / description_name(pin)))
            self.assertIn(f'python3 -m pip install "{project}=={pin["distribution_version"]}"', text)
            self.assertIn(f'python3 -m pip install --upgrade "{project}=={pin["distribution_version"]}"', text)
            self.assertIn(project.replace("-", "_"), text)
            self.assertIn("Node.js", text)
            self.assertIn(">=22", text)
            self.assertIn("THEME_FORGE_NODE_BIN", text)
            self.assertIn(">=3.9", text)
            self.assertIn("AGPL-3.0-or-later", text)
            self.assertIn("RS9-LICENSE", text)
            self.assertIn("RS9-NOTICE", text)
            for cmd in pin["bins"]:
                self.assertIn(cmd, text)
            if project == "theme-forge-stellar-burst":
                self.assertIn("MIT", text)
                self.assertIn("BSD-3-Clause", text)
                self.assertIn("manylinux_2_33_aarch64", text)
                self.assertIn("manylinux_2_33_x86_64", text)
                self.assertIn("macosx_13_0_arm64", text)
                self.assertIn("native-addon-posix-openat-v1.node", text)
                self.assertIn("--source-map", text)
                self.assertIn("--collection icons", text)
                self.assertIn("--normalize exact-common", text)
                self.assertIn("--root", text)
                self.assertIn('"jsonrpc": "2.0"', text)
                self.assertIn("tfsb.studio", text)
                self.assertIn("sessionNonce", text)
            elif project == "theme-forge-stellar-loom":
                self.assertIn("manylinux_2_28_aarch64", text)
                self.assertIn("manylinux_2_28_x86_64", text)
                self.assertIn("macosx_11_0_arm64", text)
                self.assertIn("examples/amber-forge.theme.json", text)
                self.assertIn("EMPTY_INPUT", text)
                self.assertIn("compiledCss", text)
            else:
                self.assertIn("manylinux_2_28_aarch64", text)
                self.assertIn("manylinux_2_28_x86_64", text)
                self.assertIn("macosx_11_0_arm64", text)
                self.assertIn("examples/forge-console.theme.json", text)
                self.assertNotIn("not reproduced in the authenticated release files", text)
            for forbidden in (
                "Artifact platforms:",
                "Other hosts are refused",
                "RS9_TF_PYPI",
                "/Users/",
                "rs9_theme_forge_",
                "THIRD_PARTY_NOTICES.txt",
            ):
                self.assertNotIn(forbidden, text)

    def test_description_validation_negatives(self):
        pad = b"valid markdown line\n" * 30
        bad_payloads = [
            b"",
            b"too short\n",
            pad + b"no trailing newline",
            pad + b"carriage return\r\n",
            pad + b"null byte\x00\n",
            pad + b"control char\x07\n",
            pad + b"\xff\xfeinvalid utf8\n",
            pad + b"Artifact platforms: darwin-arm64\n",
            pad + b"Other hosts are refused\n",
            pad + b"RS9_TF_PYPI_INPUTS\n",
            pad + b"/Users/operator/path\n",
            b"a" * 65536 + b"\n",
        ]
        for idx, payload_bytes in enumerate(bad_payloads):
            bad_file = self.root / f"bad-{idx}.md"
            bad_file.write_bytes(payload_bytes)
            with self.subTest(idx=idx), \
                    patch("rs9.tf_pypi_backend.physical_bytes", side_effect=lambda p, limit=32 * 1024**2, f=bad_file: physical_bytes(f, limit=limit)), \
                    self.assertRaises(AdmissionError) as caught:
                description(self.pin)
            self.assertEqual(caught.exception.code, "TF_PYPI_DESCRIPTION")

    def test_aggregate_build_verify_host_views_and_sdist_qualification_invariance(self):
        # The committed pin is already qualified, so derive genuinely distinct inputs here.
        original = copy.deepcopy(self.pin)
        unqualified = copy.deepcopy(self.pin)
        unqualified["qualified_platforms"] = []
        qualified_pin = qualified(self.pin)
        self.assertIs(type(unqualified["qualified_platforms"]), list)
        self.assertIs(type(qualified_pin["qualified_platforms"]), list)
        self.assertEqual(unqualified["qualified_platforms"], [])
        self.assertEqual(qualified_pin["qualified_platforms"], list(TARGETS))
        self.assertNotEqual(unqualified["qualified_platforms"], qualified_pin["qualified_platforms"])

        def rest(pin):
            return {key: value for key, value in pin.items() if key != "qualified_platforms"}

        self.assertEqual(set(unqualified), set(qualified_pin))
        self.assertEqual(rest(unqualified), rest(qualified_pin))
        self.assertEqual(rest(unqualified), rest(self.pin))
        unqualified_before = copy.deepcopy(unqualified)
        qualified_before = copy.deepcopy(qualified_pin)

        one = self.root / "agg_unqualified"
        two = self.root / "agg_qualified"
        agg_one = aggregate(unqualified, self.data, one)
        agg_two = aggregate(qualified_pin, self.data, two)
        self.assertEqual(self.pin, original)
        self.assertEqual(unqualified, unqualified_before)
        self.assertEqual(qualified_pin, qualified_before)
        self.assertEqual(agg_one, agg_two)
        self.assertEqual(agg_one["schema"], "rs9.tf-pypi-candidate-aggregate.v1")
        self.assertEqual(agg_one["version"], self.pin["distribution_version"])
        self.assertEqual(agg_one["upstream_version"], self.pin["version"])
        self.assertEqual(agg_one["targets"], list(TARGETS))
        self.assertIs(agg_one["publication_admitted"], False)
        self.assertEqual(len(agg_one["files"]), 4)
        self.assertEqual({p.name: p.read_bytes() for p in one.iterdir()},
                         {p.name: p.read_bytes() for p in two.iterdir()})

        with self.assertRaises(AdmissionError) as caught:
            verify_pair(self.pin, one, target="darwin-arm64")
        self.assertEqual(caught.exception.code, "TF_PYPI_FILE_SET")

        for target in TARGETS:
            view_dir = self.root / f"view-{target}"
            pair_dir = self.root / f"pair-{target}"
            view_manifest = host_view(self.pin, one, target, view_dir)
            build_pair(self.pin, self.data, pair_dir, target=target)
            pair_manifest = verify_pair(self.pin, pair_dir, target=target)
            self.assertEqual(view_manifest, pair_manifest)
            self.assertEqual({p.name: p.read_bytes() for p in view_dir.iterdir()},
                             {p.name: p.read_bytes() for p in pair_dir.iterdir()})

        with self.assertRaises(AdmissionError) as caught:
            host_view(self.pin, one, "darwin-x64", self.root / "bad-view")
        self.assertEqual(caught.exception.code, "TF_PYPI_UNSUPPORTED_PLATFORM")

    def test_verify_aggregate_negatives(self):
        base = self.root / "base"
        aggregate(self.pin, self.data, base)

        for case in ("missing-wheel", "extra-file", "other-product", "wrong-target-relabel", "symlink-dir", "cross-source"):
            work = self.root / case
            if case == "symlink-dir":
                work.symlink_to(base, target_is_directory=True)
            else:
                work.mkdir()
                for item in base.iterdir():
                    (work / item.name).write_bytes(item.read_bytes())
                if case == "missing-wheel":
                    next(work.glob("*manylinux_2_28_x86_64.whl")).unlink()
                elif case == "extra-file":
                    (work / "surplus.whl").write_bytes(b"surplus")
                elif case == "other-product":
                    (work / "theme_forge_solar_sail-0.2.1.post1-py3-none-macosx_11_0_arm64.whl").write_bytes(b"other")
                elif case == "wrong-target-relabel":
                    arm_wheel = next(work.glob("*macosx_11_0_arm64.whl"))
                    x64_wheel = next(work.glob("*manylinux_2_28_x86_64.whl"))
                    x64_wheel.write_bytes(arm_wheel.read_bytes())
                elif case == "cross-source":
                    _, other_data = fixture("theme-forge-stellar-loom", changes={"description": "mutated"})
                    mut_pin = copy.deepcopy(self.pin)
                    mut_pin.update(size=len(other_data), sha256="f" * 64)
                    sdist_path = next(work.glob("*.tar.gz"))
                    entries = sdist_entries(self.pin, self.data, target="darwin-arm64")
                    entries["upstream/" + self.pin["asset"]] = (other_data, 0o644)
                    sdist_path.write_bytes(write_tar(entries, names(self.pin)[1]))
            with self.subTest(case=case), self.assertRaises(AdmissionError) as caught:
                verify_aggregate(self.pin, work)
            if case in ("missing-wheel", "extra-file", "other-product", "symlink-dir"):
                self.assertEqual(caught.exception.code, "TF_PYPI_FILE_SET")
            elif case == "wrong-target-relabel":
                self.assertEqual(caught.exception.code, "TF_PYPI_WHEEL_MATCH")

        real_sdist = sdist_entries

        def divergent_sdist(pin, data, dependencies=None, target=None):
            entries = dict(real_sdist(pin, data, dependencies, target))
            if target == "linux-x64-gnu":
                entries["README.md"] = (entries["README.md"][0] + b"\n", 0o644)
            return entries

        with patch("rs9.tf_pypi_backend.sdist_entries", side_effect=divergent_sdist), \
                self.assertRaises(AdmissionError) as caught:
            build_aggregate(self.pin, self.data, self.root / "divergent-build")
        self.assertEqual(caught.exception.code, "TF_PYPI_SDIST_DIVERGENT")

        with patch("rs9.tf_pypi_verify.sdist_entries", side_effect=divergent_sdist), \
                self.assertRaises(AdmissionError) as caught:
            verify_aggregate(self.pin, base)
        self.assertEqual(caught.exception.code, "TF_PYPI_SDIST_DIVERGENT")

    def test_record_tamper_surplus_duplicate_and_missing_are_rejected(self):
        files = wheel_entries(self.pin, self.data, target="darwin-arm64")
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
            build_pair(self.pin, self.data, output, target="darwin-arm64")
            if mutation in {"metadata", "tag"}:
                files = wheel_entries(self.pin, self.data, target="darwin-arm64")
                target = names(self.pin)[2] + ("/METADATA" if mutation == "metadata" else "/WHEEL")
                files[target] = (b"mutated", 0o644)
                (output / (names(self.pin)[1] + "-py3-none-macosx_11_0_arm64.whl")).write_bytes(write_zip(files))
            elif mutation == "sdist":
                files = sdist_entries(self.pin, self.data, target="darwin-arm64")
                files["PKG-INFO"] = (b"mutated", 0o644)
                (output / (names(self.pin)[1] + ".tar.gz")).write_bytes(write_tar(files, names(self.pin)[1]))
            elif mutation == "extra":
                (output / "extra.whl").touch()
            else:
                next(output.glob("*.whl")).unlink()
            with self.subTest(mutation=mutation), self.assertRaises(AdmissionError):
                verify_pair(self.pin, output, target="darwin-arm64")

    def test_burst_never_emits_a_universal_or_partial_package(self):
        pin, data = fixture("theme-forge-stellar-burst")
        with self.assertRaises(AdmissionError) as caught:
            build_pair(pin, data, self.root / "burst", target="darwin-arm64")
        self.assertEqual(caught.exception.code, "TF_PYPI_NATIVE_UNQUALIFIED")
        self.assertFalse((self.root / "burst").exists())

    def test_forged_valid_record_cannot_relabel_tag_or_entrypoints(self):
        for member in ("WHEEL", "entry_points.txt", "METADATA"):
            output = self.root / ("forged-" + member)
            build_pair(self.pin, self.data, output, target="darwin-arm64")
            files = wheel_entries(self.pin, self.data, target="darwin-arm64")
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
                verify_pair(self.pin, output, target="darwin-arm64")
            self.assertEqual(caught.exception.code, "TF_PYPI_METADATA" if member == "METADATA" else "TF_PYPI_WHEEL_MATCH")

    def test_self_contained_sdist_backend_rebuilds_in_clean_process_offline(self):
        target = host_key()
        build_pair(self.pin, self.data, self.root / "dist", target=target)
        source = self.root / "source"
        source.mkdir()
        for name, (body, mode) in sdist_entries(self.pin, self.data, target=target).items():
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
        target = host_key()
        source = self.root / "source"
        for name, (body, mode) in sdist_entries(self.pin, self.data, target=target).items():
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
                         write_zip(wheel_entries(self.pin, self.data, target=target)))

    def test_sdist_backend_refuses_changed_static_project_metadata(self):
        target = host_key()
        source = self.root / "source"
        for name, (body, mode) in sdist_entries(self.pin, self.data, target=target).items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            path.chmod(mode)
        script = ("import sys;sys.path.insert(0,'_rs9_build');"
                  "from rs9 import tf_pypi_backend as b;b.build_wheel('rebuilt')")
        for name, replacement in (
            ("pyproject.toml", b'[project]\nname = "changed"\n'),
            ("README.md", b"Changed static description\n"),
            ("_rs9_build/rs9/descriptions/" + description_name(self.pin), b"Tampered packaged description\n" * 20),
        ):
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
