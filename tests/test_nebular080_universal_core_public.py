"""Non-admitting public-repository tests for the Nebular 0.8 universal core.

The test is intentionally repository-root relative.  It imports only the
``rs9`` package under this repository's ``src`` tree and reads legal files
from this repository root.  Tiny synthetic archives exercise unit contracts;
they do not mint product capture, native capabilities, hosted receipts, or
publication evidence.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock


REPOSITORY = Path(__file__).resolve().parents[1]
SRC = REPOSITORY / "src"
sys.path.insert(0, str(SRC))

from rs9 import nebular080_product_native as native  # noqa: E402
from rs9 import nebular080_universal_consumer as consumer  # noqa: E402
from rs9 import nebular080_universal_fetch as fetch  # noqa: E402
from rs9 import nebular080_universal_launcher as launcher  # noqa: E402
from rs9 import nebular080_universal_profile as profile  # noqa: E402
from rs9 import wheel_nebular080_universal as wheel  # noqa: E402
from rs9.archives import inspect_archive  # noqa: E402
from rs9.errors import ContractError  # noqa: E402
from rs9.tf_pypi_archive import AdmissionError  # noqa: E402


# The archive/cache contracts reject symlinked ancestors.  Normalize the
# stdlib temporary root so a host `/tmp` alias does not affect the fixture.
tempfile.tempdir = str(Path(tempfile.gettempdir()).resolve())


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tar_bytes(target: str) -> bytes:
    if target == "darwin-arm64":
        root = "Theme Forge Nebular Fusion.app"
        directories = (
            root,
            f"{root}/Contents",
            f"{root}/Contents/Resources",
            f"{root}/Contents/Resources/bin",
            f"{root}/Contents/MacOS",
        )
        files = {
            f"{root}/Contents/Resources/bin/tfnf": b"#!/bin/sh\nexit 0\n",
            f"{root}/Contents/MacOS/theme-forge-nebular-fusion": b"#!/bin/sh\nexit 0\n",
        }
    else:
        root = "theme-forge-nebular-fusion"
        directories = (root, f"{root}/bin")
        files = {
            f"{root}/bin/tfnf": b"#!/bin/sh\nexit 0\n",
            f"{root}/bin/theme-forge-nebular-fusion": b"#!/bin/sh\nexit 0\n",
        }
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name in directories:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.mtime = 0
            archive.addfile(info)
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def _fixture(root: Path) -> tuple[Path, Path, dict]:
    archives = root / "assets"
    archives.mkdir()
    triples = {
        "darwin-arm64": "aarch64-apple-darwin.app",
        "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
        "linux-x64-gnu": "x86_64-unknown-linux-gnu",
    }
    targets = {}
    for index, (target, triple) in enumerate(triples.items(), 1):
        data = _tar_bytes(target)
        name = f"theme-forge-nebular-fusion-v0.8.0-{triple}.tar.gz"
        path = archives / name
        path.write_bytes(data)
        manifest = inspect_archive(path, commands={})
        if target == "darwin-arm64":
            root_name = "Theme Forge Nebular Fusion.app"
            shell = root_name + "/Contents/Resources/bin/tfnf"
            gui = root_name + "/Contents/MacOS/theme-forge-nebular-fusion"
            family, arch, minimum_os, minimum_glibc = "darwin", "aarch64", "13.3", None
        else:
            root_name = "theme-forge-nebular-fusion"
            shell = root_name + "/bin/tfnf"
            gui = root_name + "/bin/theme-forge-nebular-fusion"
            family, arch, minimum_os, minimum_glibc = (
                "linux",
                "aarch64" if "arm64" in target else "x86_64",
                None,
                "2.36",
            )
        targets[target] = {
            "family": family,
            "arch": arch,
            "minimum_os": minimum_os,
            "minimum_glibc": minimum_glibc,
            "asset": {
                "id": 8000 + index,
                "name": name,
                "size": len(data),
                "sha256": _sha(data),
                "url": fetch.BASE_URL + name,
            },
            "manifest_sha256": manifest["manifest_sha256"],
            "root": root_name,
            "shell_target": shell,
            "gui_target": gui,
        }
    inputs = {
        "schema": profile.SCHEMAS["runtime_inputs"],
        "project": profile.PRODUCT,
        "version": profile.VERSION,
        "upstream_release": {
            "repository": profile.REPOSITORY,
            "tag": profile.TAG,
            "commit": native.TESTED_COMMIT,
            "tree": native.TESTED_TREE,
        },
        "product_native_reference": native.reference(),
        "targets": targets,
    }
    inputs_path = root / "runtime-inputs.json"
    inputs_path.write_bytes(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode())
    description = root / "description.md"
    description.write_text("# Nebular 0.8.0\n\nA test-only description.\n", encoding="utf-8")
    return inputs_path, description, inputs


class Universal080CorePublicTests(unittest.TestCase):
    def test_repository_root_supplies_source_and_legal_inputs(self) -> None:
        self.assertEqual(REPOSITORY, Path(__file__).resolve().parents[1])
        for name in (
            "nebular080_universal_profile.py",
            "nebular080_universal_fetch.py",
            "nebular080_universal_launcher.py",
            "wheel_nebular080_universal.py",
            "nebular080_universal_consumer.py",
            "nebular080_product_native.py",
        ):
            path = SRC / "rs9" / name
            self.assertTrue(path.is_file(), name)
            self.assertFalse(path.is_symlink(), name)
        for name in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"):
            path = REPOSITORY / name
            self.assertTrue(path.is_file(), name)
            self.assertFalse(path.is_symlink(), name)

    def test_real_wheel_and_embedded_launcher_readback(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs_path, description, inputs = _fixture(root)
            result = wheel.build_universal_wheel(
                inputs_path, root / "assets", description, root / "dist", legal_root=REPOSITORY,
            )
            wheel_path = root / "dist" / wheel.FILENAME
            raw = wheel_path.read_bytes()
            self.assertEqual(result["filename"], wheel.FILENAME)
            self.assertFalse(result["builder_can_publish"])
            snapshot = consumer.inspect_universal_wheel(
                raw,
                inputs_path.read_bytes(),
                repository=REPOSITORY,
                description=description.read_bytes(),
                legal_root=REPOSITORY,
            )
            self.assertEqual(snapshot["wheel"]["tag"], "py3-none-any")
            self.assertFalse(snapshot["publication_admitted"])
            extract = root / "extracted"
            with zipfile.ZipFile(wheel_path) as archive:
                archive.extractall(extract)
                launcher_source = archive.read("theme_forge_nebular_fusion/launcher.py")
                entrypoint = archive.read(wheel.DIST_INFO + "/entry_points.txt")
                metadata = archive.read(wheel.DIST_INFO + "/METADATA")
            from rs9 import nebular080_publication_coordinates as coordinates
            self.assertEqual(metadata.count(
                ("License-Expression: " + coordinates.EXPECTED_LICENSE_EXPRESSION + "\n").encode()
            ), 1)
            self.assertEqual(metadata.count(
                ("Requires-Python: " + coordinates.EXPECTED_REQUIRES_PYTHON + "\n").encode()
            ), 1)
            self.assertIn(b"def _platform_key", launcher_source)
            self.assertIn(b"def _cached_archive", launcher_source)
            self.assertNotIn(b"raise SystemExit(0)", launcher_source)
            self.assertEqual(
                entrypoint,
                b"[console_scripts]\ntfnf = theme_forge_nebular_fusion.launcher:main_tfnf\n",
            )
            env = dict(os.environ)
            env["PYTHONPATH"] = str(extract)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from theme_forge_nebular_fusion.launcher import main_tfnf; main_tfnf()",
                    "--version",
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "theme-forge-nebular-fusion 0.8.0")

            cache = root / "cache"
            cached = cache / "archives" / (inputs["targets"]["linux-x64-gnu"]["asset"]["sha256"] + ".tgz")
            cached.parent.mkdir(parents=True)
            shutil.copy2(root / "assets" / inputs["targets"]["linux-x64-gnu"]["asset"]["name"], cached)
            script = (
                "import os; from pathlib import Path; "
                "from theme_forge_nebular_fusion import launcher; "
                "spec,manifest=launcher._runtime_spec('linux-x64-gnu'); "
                "helpers=launcher._materializer(); "
                "archive=launcher._cached_archive(spec['asset'], Path(os.environ['CACHE']), helpers); "
                "targets=launcher._materialized_paths(archive, Path(os.environ['CACHE']), spec, manifest, helpers); "
                "assert len(targets)==2 and all(path.is_file() for path in targets)"
            )
            env["CACHE"] = str(cache)
            completed = subprocess.run(
                [sys.executable, "-c", script],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_fetch_rejects_cross_version_and_tampered_bytes(self) -> None:
        data = b"verified-fetch-bytes"
        name = "theme-forge-nebular-fusion-v0.8.0-x86_64-unknown-linux-gnu.tar.gz"
        good = {
            "id": 1,
            "name": name,
            "size": len(data),
            "sha256": _sha(data),
            "url": fetch.BASE_URL + name,
        }
        fetch._validate_asset(good)

        class Response:
            status = 200
            headers = {"Content-Encoding": "identity", "Transfer-Encoding": "identity"}

            def read1(self, _limit):
                if getattr(self, "done", False):
                    return b""
                self.done = True
                return data

            def geturl(self):
                return good["url"]

            def close(self):
                return None

        class Opener:
            def __init__(self):
                self.calls = 0

            def open(self, _request, timeout):
                del timeout
                self.calls += 1
                return Response()

        with tempfile.TemporaryDirectory() as temporary:
            opener = Opener()
            first = fetch.fetch_archive(good, Path(temporary), opener=opener, clock=lambda: 0.0)
            second = fetch.fetch_archive(good, Path(temporary), opener=opener, clock=lambda: 0.0)
            self.assertTrue(first.downloaded)
            self.assertFalse(second.downloaded)
            self.assertEqual(opener.calls, 1)
            self.assertEqual(first.archive.read_bytes(), data)

        class BadOpener(Opener):
            def open(self, _request, timeout):
                del timeout
                self.calls += 1

                class BadResponse(Response):
                    def read1(self, _limit):
                        if getattr(self, "done", False):
                            return b""
                        self.done = True
                        return b"tampered"

                return BadResponse()

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(fetch.RuntimeDownloadError) as context:
                fetch.fetch_archive(good, Path(temporary), opener=BadOpener(), clock=lambda: 0.0)
            self.assertEqual(context.exception.code, "TFNF_RUNTIME_DIGEST")
        with self.assertRaises(fetch.RuntimeDownloadError):
            fetch._validate_asset({**good, "name": name.replace("0.8.0", "0.7.1")})
        with self.assertRaises(fetch.RuntimeDownloadError):
            fetch._validate_asset({**good, "url": "https://example.invalid/" + name})

    def test_080_floors_and_exact_native_reference_are_closed(self) -> None:
        self.assertEqual(profile.VERSION, "0.8.0")
        self.assertEqual(profile.TAG, "v0.8.0")
        with self.assertRaises(AdmissionError):
            profile.validate_versioned_coordinates({
                "version": "0.7.1",
                "tag": "v0.7.1",
                "target": "linux-x64-gnu",
            })
        with (
            mock.patch.object(launcher.sys, "platform", "darwin"),
            mock.patch.object(launcher.platform, "machine", return_value="arm64"),
            mock.patch.object(launcher.platform, "mac_ver", return_value=("13.3.0", "", "")),
        ):
            self.assertEqual(launcher._platform_key(), "darwin-arm64")
        with (
            mock.patch.object(launcher.sys, "platform", "linux"),
            mock.patch.object(launcher.platform, "machine", return_value="x86_64"),
            mock.patch.object(launcher.os, "confstr", return_value="glibc 2.36"),
        ):
            self.assertEqual(launcher._platform_key(), "linux-x64-gnu")
        with tempfile.TemporaryDirectory() as temporary:
            _inputs_path, _description, inputs = _fixture(Path(temporary))
            bad = copy.deepcopy(inputs)
            bad["product_native_reference"] = {}
            with self.assertRaises(ContractError):
                wheel._inputs(json.dumps(bad).encode())
            self.assertEqual(inputs["product_native_reference"], native.reference())


if __name__ == "__main__":
    unittest.main()
