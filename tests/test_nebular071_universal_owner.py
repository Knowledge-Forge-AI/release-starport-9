"""Non-admitting tests for the real Nebular 0.7.1 universal owner closure.

The fixture archives are deliberately tiny and synthetic.  They exercise the
same archive inspector, wheel builder, embedded launcher, fetch pin checker,
and fail-closed command seams used by the production route; they are not
native qualification evidence.
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

_CANDIDATE = Path(__file__).resolve().parents[1]
tempfile.tempdir = str(Path(tempfile.gettempdir()).resolve())
sys.path.insert(0, str(_CANDIDATE / "src"))
import rs9  # noqa: E402

from rs9 import nebular071_universal_fetch as fetch  # noqa: E402
from rs9 import nebular071_universal_launcher as launcher  # noqa: E402
from rs9 import nebular071_universal_profile as profile  # noqa: E402
from rs9 import nebular071_universal_workflow as workflow  # noqa: E402
from rs9 import tf_pypi_nebular071_universal as commands  # noqa: E402
from rs9 import wheel_nebular071_universal as wheel  # noqa: E402
from rs9 import nebular071_universal_consumer as consumer  # noqa: E402
from rs9.archives import inspect_archive  # noqa: E402
from rs9.errors import ContractError  # noqa: E402
from rs9.tf_pypi_archive import AdmissionError  # noqa: E402




def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tar_bytes(target: str) -> bytes:
    if target == "darwin-arm64":
        root = "Theme Forge Nebular Fusion.app"
        directories = (
            root, f"{root}/Contents", f"{root}/Contents/Resources",
            f"{root}/Contents/Resources/bin", f"{root}/Contents/MacOS",
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
    rows = {
        "darwin-arm64": "aarch64-apple-darwin.app",
        "linux-arm64-gnu": "aarch64-unknown-linux-gnu",
        "linux-x64-gnu": "x86_64-unknown-linux-gnu",
    }
    targets = {}
    for index, (target, triple) in enumerate(rows.items(), 1):
        data = _tar_bytes(target)
        name = f"theme-forge-nebular-fusion-v0.7.1-{triple}.tar.gz"
        path = archives / name
        path.write_bytes(data)
        manifest = inspect_archive(path, commands={})
        if target == "darwin-arm64":
            root_name = "Theme Forge Nebular Fusion.app"
            shell = root_name + "/Contents/Resources/bin/tfnf"
            gui = root_name + "/Contents/MacOS/theme-forge-nebular-fusion"
            family, arch, minimum_os, minimum_glibc = "darwin", "aarch64", "13.0", None
        else:
            root_name = "theme-forge-nebular-fusion"
            shell = root_name + "/bin/tfnf"
            gui = root_name + "/bin/theme-forge-nebular-fusion"
            family, arch, minimum_os, minimum_glibc = "linux", (
                "aarch64" if "arm64" in target else "x86_64"
            ), None, "2.36"
        targets[target] = {
            "family": family, "arch": arch, "minimum_os": minimum_os,
            "minimum_glibc": minimum_glibc,
            "asset": {
                "id": 7100 + index, "name": name, "size": len(data),
                "sha256": _sha(data), "url": fetch.BASE_URL + name,
            },
            "manifest_sha256": manifest["manifest_sha256"],
            "root": root_name, "shell_target": shell, "gui_target": gui,
        }
    inputs = {
        "schema": profile.SCHEMAS["runtime_inputs"],
        "project": profile.PRODUCT, "version": profile.VERSION,
        "upstream_release": {
            "repository": profile.REPOSITORY.replace("release-starport-9", "theme-forge-nebular-fusion"),
            "tag": profile.TAG, "commit": "a" * 40, "tree": "b" * 40,
        },
        "product_native_reference": __import__("rs9.nebular071_product_native", fromlist=["reference"]).reference(),
        "targets": targets,
    }
    inputs_path = root / "runtime-inputs.json"
    inputs_path.write_bytes(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode())
    description = root / "description.md"
    description.write_text("# Nebular 0.7.1\n\nA test-only description.\n", encoding="utf-8")
    for name, body in {
        "LICENSE": "AGPL-3.0-or-later\n",
        "NOTICE": "Test notice\n",
        "COMMERCIAL-LICENSE.md": "Commercial terms are retained in the product source.\n",
    }.items():
        (root / name).write_text(body, encoding="utf-8")
    return inputs_path, description, inputs


class Universal071OwnerTests(unittest.TestCase):
    def test_real_wheel_contains_launcher_and_entrypoint_and_is_self_contained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs_path, description, inputs = _fixture(root)
            result = wheel.build_universal_wheel(
                inputs_path, root / "assets", description, root / "dist", legal_root=root,
            )
            wheel_path = root / "dist" / wheel.FILENAME
            raw = wheel_path.read_bytes()
            self.assertEqual(result["filename"], wheel.FILENAME)
            self.assertFalse(result["builder_can_publish"])
            snapshot = consumer.inspect_universal_wheel(
                raw, inputs_path.read_bytes(), repository=_CANDIDATE,
                description=description.read_bytes(), legal_root=root,
            )
            self.assertEqual(snapshot["wheel"]["tag"], "py3-none-any")
            self.assertFalse(snapshot["publication_admitted"])
            extract = root / "extracted"
            with zipfile.ZipFile(wheel_path) as archive:
                archive.extractall(extract)
                launcher_source = archive.read("theme_forge_nebular_fusion/launcher.py")
                entrypoint = archive.read(wheel.DIST_INFO + "/entry_points.txt")
            self.assertIn(b"def _platform_key", launcher_source)
            self.assertIn(b"def _cached_archive", launcher_source)
            self.assertNotIn(b"raise SystemExit(0)", launcher_source)
            self.assertEqual(
                entrypoint,
                b"[console_scripts]\ntfnf = theme_forge_nebular_fusion.launcher:main_tfnf\n",
            )
            env = dict(os.environ)
            env["PYTHONPATH"] = str(extract)
            command = [
                sys.executable, "-c",
                "from theme_forge_nebular_fusion.launcher import main_tfnf; main_tfnf()",
                "--version",
            ]
            completed = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "theme-forge-nebular-fusion 0.7.1")

            # Reuse the same extracted wheel in a subprocess with no rs9 from
            # the builder checkout: index, cache, materialization, and target
            # resolution are exercised without network or native execution.
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
                "assert len(targets)==2 and all(path.is_file() for path in targets); print(targets[0])"
            )
            env.update({"CACHE": str(cache), "PYTHONPATH": str(extract)})
            completed = subprocess.run([sys.executable, "-c", script], env=env,
                                       capture_output=True, text=True, timeout=15)
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_fetch_pin_and_cross_version_workflow_refuse_without_real_inputs(self):
        data = b"verified-fetch-bytes"
        good = {
            "id": 1,
            "name": "theme-forge-nebular-fusion-v0.7.1-x86_64-unknown-linux-gnu.tar.gz",
            "size": len(data), "sha256": _sha(data),
            "url": fetch.BASE_URL + "theme-forge-nebular-fusion-v0.7.1-x86_64-unknown-linux-gnu.tar.gz",
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
            fetch._validate_asset({**good, "name": good["name"].replace("0.7.1", "0.7.0"),
                                   "url": good["url"].replace("0.7.1", "0.7.0")})
        self.assertEqual(workflow.validate_workflow_dispatch("0.7.1", profile.QUALIFY_MODE)["release"], "0.7.1")
        with self.assertRaises(AdmissionError):
            workflow.validate_workflow_dispatch("0.7.0", "universal-qualify")
        with self.assertRaises(AdmissionError):
            workflow.validate_workflow_dispatch("0.7.1", "qualify")
        self.assertIn("universal_publication_071", workflow.publication_job_text())
        rendered = workflow.qualify_jobs_text()
        self.assertEqual(rendered.count("\n  universal_"), 8)
        self.assertNotIn("0.7.0", rendered)
        self.assertNotIn("prepare-public-inputs-070", rendered)
        self.assertNotIn("RS9_TF_PRODUCER_", rendered)
        with self.assertRaises((ContractError, AdmissionError, FileNotFoundError, OSError)):
            commands.build_bundle(
                Path("missing-qualification-inputs.json"), Path("missing-inrun"),
                Path("missing-output"), repository=_CANDIDATE,
                expected_commit="a" * 40, require_clean=True,
            )

    def test_real_readback_and_consumer_paths_fail_closed_without_hosted_receipts(self):
        with self.assertRaises((ContractError, OSError, FileNotFoundError)):
            commands.read_matrix_inputs(
                Path("missing-bundle"), Path("missing-inputs"), Path("missing-inrun"),
                Path("missing-receipts"), Path("missing-floor"), Path("missing-work"),
                repository=_CANDIDATE, source={"commit": "a" * 40, "tree": "b" * 40},
                run_id="1", run_attempt="1",
            )
        with self.assertRaises(ContractError):
            commands._hosted_context(
                {"commit": "a" * 40, "tree": "b" * 40}, "1", "1",
            )
        with self.assertRaises(AdmissionError):
            profile.validate_versioned_coordinates({
                "version": "0.7.0", "tag": "v0.7.0", "target": "linux-x64-gnu",
            })

    def test_source_closure_has_no_070_admission_imports_or_toy_owner_stubs(self):
        forbidden = {
            "tf_pypi_consumer", "tf_pypi_nebular070_publish", "nebular070_universal_consumer",
            "nebular070_smoke_support", "nebular070_universal_workflow", "nebular070_universal_history",
            "nebular070_universal_publication",
        }
        modules = sorted((_CANDIDATE / "src" / "rs9").glob("*071*.py"))
        self.assertGreaterEqual(len(modules), 20)
        for path in modules:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("raise SystemExit(0)", text, path.name)
            self.assertNotIn("runtime fetch is supplied", text, path.name)
            # The isolated historical reader must name the older release. It
            # supplies no current payload/consumer/publication admission.
            if path.name not in {"nebular071_universal_profile.py", "nebular071_predecessor_history.py"}:
                self.assertNotIn("nebular070", text, path.name)
                self.assertNotIn("0.7.0", text, path.name)
            tree = ast.parse(text, filename=str(path))
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("rs9."):
                    imports.add(node.module.rsplit(".", 1)[-1])
                elif isinstance(node, ast.ImportFrom) and node.module == "rs9":
                    imports.update(alias.name for alias in node.names)
                elif isinstance(node, ast.Import):
                    imports.update(alias.name.rsplit(".", 1)[-1] for alias in node.names if alias.name.startswith("rs9."))
            if path.name == "nebular071_predecessor_history.py":
                historical = {"tf_pypi_nebular070_publish", "nebular070_universal_history"}
                self.assertTrue((forbidden - historical).isdisjoint(imports), (path.name, sorted(imports & (forbidden - historical))))
            else:
                self.assertTrue(forbidden.isdisjoint(imports), (path.name, sorted(imports & forbidden)))


if __name__ == "__main__":
    unittest.main()
