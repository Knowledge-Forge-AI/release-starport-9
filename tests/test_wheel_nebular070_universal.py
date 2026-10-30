"""Pure archive/packaging fixtures; no native application is executed."""

import ast
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

from rs9.archives import inspect_archive
from rs9.errors import ContractError
from rs9.verify_wheel import verify_wheel_record_bidirectional
from rs9.wheel_native import get_embedded_rs9_helpers
from rs9.wheel_nebular070_universal import build_universal_wheel


class UniversalWheelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.archives = self.root / "archives"
        self.archives.mkdir()
        self.legal = self.root / "legal"
        self.legal.mkdir()
        for name in ("LICENSE", "NOTICE", "COMMERCIAL-LICENSE.md"):
            (self.legal / name).write_text("Synthetic legal fixture\n")
        self.description = self.root / "description.md"
        self.description.write_text("# Synthetic application\n\nRun `tfnf install-runtime`.\n")
        targets = {}
        for target, triple in (("darwin-arm64", "aarch64-apple-darwin.app"),
                               ("linux-arm64-gnu", "aarch64-unknown-linux-gnu"),
                               ("linux-x64-gnu", "x86_64-unknown-linux-gnu")):
            darwin = target == "darwin-arm64"
            root = "Theme Forge Nebular Fusion.app" if darwin else "theme-forge-nebular-fusion"
            shell = root + ("/Contents/Resources/bin/tfnf" if darwin else "/bin/tfnf")
            gui = root + ("/Contents/MacOS/theme-forge-nebular-fusion" if darwin else "/bin/theme-forge-nebular-fusion")
            files = {shell: b"synthetic shell", gui: b"synthetic GUI"}
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w:gz") as archive:
                directories = {str(p) for name in files for p in PurePosixPath(name).parents if str(p) != "."}
                for name in sorted(directories, key=lambda x: (len(PurePosixPath(x).parts), x)):
                    info = tarfile.TarInfo(name)
                    info.type, info.mode = tarfile.DIRTYPE, 0o755
                    archive.addfile(info)
                for name, body in sorted(files.items()):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode = len(body), 0o755
                    archive.addfile(info, io.BytesIO(body))
            name = "theme-forge-nebular-fusion-v0.7.0-" + triple + ".tar.gz"
            path = self.archives / name
            path.write_bytes(data.getvalue())
            manifest = inspect_archive(path, commands={})
            targets[target] = {
                "family": "darwin" if darwin else "linux",
                "arch": "x86_64" if target == "linux-x64-gnu" else "aarch64",
                "minimum_os": "13.0" if darwin else None,
                "minimum_glibc": None if darwin else "2.36",
                "root": root, "shell_target": shell, "gui_target": gui,
                "manifest_sha256": manifest["manifest_sha256"],
                "asset": {"id": 1, "name": name, "size": path.stat().st_size,
                          "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                          "url": "https://github.com/Knowledge-Forge-AI/theme-forge-nebular-fusion/releases/download/v0.7.0/" + name},
            }
        self.inputs = {"schema": "rs9.nebular070-universal-runtime-inputs.v1",
                       "project": "theme-forge-nebular-fusion", "version": "0.7.0",
                       "upstream_release": {"repository": "Knowledge-Forge-AI/theme-forge-nebular-fusion",
                                            "tag": "v0.7.0", "commit": "a" * 40, "tree": "b" * 40},
                       "native_payload_qualification": {"run_id": 1, "repository": "Knowledge-Forge-AI/release-starport-9",
                                                        "source_commit": "c" * 40, "source_tree": "d" * 40,
                                                        "qualifies_native_payloads_only": True},
                       "targets": targets}
        self.spec = self.root / "runtime-inputs.json"

    def build(self, name="out"):
        self.spec.write_text(json.dumps(self.inputs, sort_keys=True, indent=2) + "\n")
        return build_universal_wheel(
            self.spec, self.archives, self.description, self.root / name,
            legal_root=self.legal,
        )

    def test_exactly_one_pure_python_wheel_has_valid_record_and_license(self):
        result = self.build()
        self.assertEqual(result["filename"], "theme_forge_nebular_fusion-0.7.0-py3-none-any.whl")
        self.assertFalse(result["builder_can_publish"])
        path = self.root / "out" / result["filename"]
        verify_wheel_record_bidirectional(path)
        with zipfile.ZipFile(path) as archive:
            wheel = archive.read("theme_forge_nebular_fusion-0.7.0.dist-info/WHEEL")
            self.assertIn(b"Root-Is-Purelib: true\n", wheel)
            self.assertIn(b"Tag: py3-none-any\n", wheel)
            metadata = archive.read("theme_forge_nebular_fusion-0.7.0.dist-info/METADATA")
            self.assertIn(b"License-Expression: AGPL-3.0-or-later\n", metadata)
            self.assertIn(b"Requires-Python: >=3.10\n", metadata)
            self.assertNotIn(b"Requires-Dist:", metadata)
            self.assertFalse(any(name.endswith((".tgz", ".tar.gz", ".so", ".dylib", ".dll")) for name in archive.namelist()))
            for name in archive.namelist():
                archive.read(name).decode("utf-8")

    def test_deterministic_build_and_unchanged_reviewed_helper_closure(self):
        first = self.build("first")
        second = self.build("second")
        a, b = self.root / "first" / first["filename"], self.root / "second" / second["filename"]
        self.assertEqual(a.read_bytes(), b.read_bytes())
        with zipfile.ZipFile(a) as archive:
            for name, source in get_embedded_rs9_helpers().items():
                self.assertEqual(archive.read("theme_forge_nebular_fusion/_isolated/" + name), source)
            for name in archive.namelist():
                if name.endswith(".py"):
                    ast.parse(archive.read(name).decode(), feature_version=(3, 10))

    def test_index_and_manifest_resources_are_identity_bound(self):
        result = self.build()
        with zipfile.ZipFile(self.root / "out" / result["filename"]) as archive:
            raw_index = archive.read("theme_forge_nebular_fusion/runtime-index.json")
            index = json.loads(raw_index)
            launcher = archive.read("theme_forge_nebular_fusion/launcher.py")
            self.assertIn(hashlib.sha256(raw_index).hexdigest().encode(), launcher)
            self.assertNotIn(b"__TFNF_INDEX_SHA256__", launcher)
            for target, spec in index["targets"].items():
                manifest = archive.read("theme_forge_nebular_fusion/runtimes/" + target + ".json")
                self.assertEqual(hashlib.sha256(manifest).hexdigest(), spec["manifest_resource_sha256"])
                self.assertEqual(json.loads(manifest)["manifest_sha256"], spec["manifest_sha256"])

    def test_changed_archive_or_manifest_pin_is_refused(self):
        target = self.inputs["targets"]["linux-x64-gnu"]
        path = self.archives / target["asset"]["name"]
        original = path.read_bytes()
        path.write_bytes(original + b"changed")
        with self.assertRaises(ContractError):
            self.build("changed-archive")
        path.write_bytes(original)
        target["manifest_sha256"] = "0" * 64
        with self.assertRaises(ContractError):
            self.build("changed-manifest")

    def test_unsupported_asset_target_or_version_cannot_be_packaged(self):
        self.inputs["targets"]["linux-x64-gnu"]["asset"]["url"] = "https://unapproved.invalid/runtime"
        with self.assertRaises(ContractError):
            self.build()
        del self.inputs["targets"]["darwin-arm64"]
        with self.assertRaises(ContractError):
            self.build("missing-target")
        self.inputs["version"] = "0.8.0"
        with self.assertRaises(ContractError):
            self.build("wrong-version")

    def test_builder_does_not_overwrite_existing_artifact_or_follow_input_symlinks(self):
        result = self.build()
        path = self.root / "out" / result["filename"]
        original = path.read_bytes()
        with self.assertRaises(ContractError):
            self.build()
        self.assertEqual(path.read_bytes(), original)
        item = self.inputs["targets"]["linux-arm64-gnu"]["asset"]
        archive = self.archives / item["name"]
        moved = archive.with_name("saved")
        archive.rename(moved)
        archive.symlink_to(moved)
        with self.assertRaises(ContractError):
            self.build("symlink-input")

    def installed_site(self):
        result = self.build()
        site = self.root / "site"
        with zipfile.ZipFile(self.root / "out" / result["filename"]) as archive:
            archive.extractall(site)
        return site

    def test_installed_synthetic_package_sets_up_and_repairs_offline(self):
        site = self.installed_site()
        archive = self.archives / self.inputs["targets"]["darwin-arm64"]["asset"]["name"]
        script = r'''
import io,json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
os.environ["THEME_FORGE_CACHE_DIR"]=sys.argv[2]
from theme_forge_nebular_fusion import launcher as launch
launch._platform_key=lambda:"darwin-arm64"
helpers=launch._materializer()
from theme_forge_nebular_fusion import _fetch as fetch
data=Path(sys.argv[3]).read_bytes()
calls={"network":0,"exec":[]}
class Response:
 status=200
 headers={"Content-Length":str(len(data))}
 def __init__(self,url):self.url=url;self.body=io.BytesIO(data)
 def geturl(self):return self.url
 def read1(self,n):return self.body.read(n)
 def close(self):self.body.close()
class Opener:
 def open(self,request,timeout):
  calls["network"]+=1
  return Response(request.full_url)
fetch._opener=lambda *args:Opener()
launch.run_launcher(["install-runtime","--json"])
launch.run_launcher(["install-runtime","--json"])
launch._fetcher=lambda:(_ for _ in ()).throw(AssertionError("implicit fetch"))
spec,manifest=launch._runtime_spec("darwin-arm64")
root=Path(sys.argv[2])/"entries"/spec["manifest_sha256"]/"payload"/spec["root"]
gui=root/"Contents/MacOS/theme-forge-nebular-fusion"
gui.write_bytes(b"synthetic tamper")
launch.run_launcher(["--path"])
assert gui.read_bytes()==b"synthetic GUI"
launch.os.execv=lambda executable,args:calls["exec"].append([Path(executable).name,args[1:]])
launch.run_launcher(["--fixture","value"])
print(json.dumps(calls,sort_keys=True))
'''
        result = subprocess.run(
            [sys.executable, "-I", "-c", script, str(site), str(self.root / "runtime-cache"), str(archive)],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertTrue(json.loads(lines[0])["downloaded"])
        self.assertFalse(json.loads(lines[1])["downloaded"])
        self.assertEqual(json.loads(lines[-1]), {"network": 1, "exec": [["tfnf", ["--fixture", "value"]]]})

    def test_installed_help_and_version_do_not_import_posix_or_network_helpers(self):
        site = self.installed_site()
        script = r'''
import builtins,sys
sys.path.insert(0,sys.argv[1])
original=builtins.__import__
def guarded(name,*args,**kwargs):
 if name=="fcntl" or name.startswith("urllib.request"):raise AssertionError("unexpected helper")
 return original(name,*args,**kwargs)
builtins.__import__=guarded
sys.platform="win32"
from theme_forge_nebular_fusion import launcher
assert launcher.run_launcher(["--help"])==0
assert launcher.run_launcher(["--version"])==0
assert "theme_forge_nebular_fusion._fetch" not in sys.modules
'''
        result = subprocess.run([sys.executable, "-I", "-c", script, str(site)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0.7.0", result.stdout)
