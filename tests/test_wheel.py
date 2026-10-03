"""Wheel bytes and real offline venv boundaries; synthetic payloads only."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

from rs9.errors import ContractError
from rs9.scratch import canonical
from rs9.wheel import build_wheel, inspect_wheel, resolve_wheel_tag
from rs9.release_core import digest

LICENSES = {"LICENSE": b"Synthetic AGPL fixture licence.\n", "NOTICE": b"Synthetic notice.\n"}
LOOM = {"package/bin/tfsl.js": b"console.log('synthetic-loom 0.4.0')\n",
        "package/bin/tfsl-batch.js": b"console.log(JSON.stringify({error:{code:'EMPTY_INPUT'}})); process.exit(1)\n"}


class WheelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def build(self, directory, *, payload=None, **kw):
        return build_wheel("theme-forge-stellar-loom", "0.4.0", payload or LOOM,
             {p:0o755 for p in (payload or LOOM)}, output_dir=directory,
             release_hash=digest(b"synthetic-release"), license_files=LICENSES, **kw)

    def test_double_build_bytes_record_modes_and_metadata(self):
        a=self.build(self.root/"a"); b=self.build(self.root/"b")
        self.assertEqual(a.wheel_bytes,b.wheel_bytes)
        inventory=inspect_wheel(a.wheel_path)
        self.assertTrue(inventory["record_valid"])
        self.assertFalse(a.can_publish)
        self.assertEqual(inventory["metadata"]["Version"],"0.4.0")
        self.assertEqual(inventory["metadata"]["License-Expression"],"AGPL-3.0-or-later")
        self.assertEqual(inventory["metadata"]["License-File"],["LICENSE","NOTICE"])
        self.assertNotIn("External runtime requirement",inventory["metadata"])
        with zipfile.ZipFile(a.wheel_path) as wheel:
            self.assertEqual(wheel.namelist(),sorted(wheel.namelist()))
            for p,data in LOOM.items():
                member="theme_forge_stellar_loom/payload/"+p
                self.assertEqual(wheel.read(member),data)
                self.assertEqual((wheel.getinfo(member).external_attr>>16)&0o777,0o755)
            self.assertIn("Node.js >= 22",wheel.read("theme_forge_stellar_loom-0.4.0.dist-info/METADATA").decode())

    def test_missing_commands_licence_provenance_version_and_bad_metadata(self):
        with self.assertRaises(ContractError): self.build(self.root,payload={"package/bin/tfsl.js":b""})
        args=("theme-forge-solar-sail","0.2.1",{"package/bin/tfss.js":b""})
        for opts in ({},{"release_hash":"a"*64},{"release_hash":"a"*64,"license_files":{"LICENSE\nInjected: value":b"x"}}):
            with self.assertRaises(ContractError): build_wheel(*args,output_dir=self.root,**opts)
        with self.assertRaises(ContractError):
            build_wheel("theme-forge-stellar-loom","0.4.1",LOOM,output_dir=self.root,release_hash="a"*64,license_files=LICENSES)
        with self.assertRaises(ContractError): self.build(self.root,summary="summary\nInjected: value")
        with self.assertRaises(ContractError): self.build(self.root,console_scripts={"evil":"bad\nheader"})

    def test_tags_withhold_unproven_fallback_and_native(self):
        self.assertEqual(resolve_wheel_tag("theme-forge-stellar-loom"),"py3-none-any")
        for kwargs in ({},{"platform_tag":"any"},{"js_fallback":True,"evidence":{"verdict":"pass"}}):
            with self.assertRaises(ContractError): resolve_wheel_tag("theme-forge-stellar-burst",**kwargs)
        self.assertEqual(resolve_wheel_tag("theme-forge-stellar-burst",platform_tag="manylinux_2_34_x86_64"),"py3-none-manylinux_2_34_x86_64")
        for tag in (None,"linux_x86_64","macosx_11_0_x86_64","macosx_11_0_arm64"):
            with self.assertRaises(ContractError): resolve_wheel_tag("theme-forge-nebular-fusion",platform_tag=tag,mode_restoration_verified=True)
        with self.assertRaises(ContractError): resolve_wheel_tag("unknown-product")

    def test_path_safety_and_exclusive_destination(self):
        self.build(self.root)
        with self.assertRaises(ContractError): self.build(self.root)
        for path in ("../escape","/absolute","a\\b"):
            with self.assertRaises(ContractError): self.build(self.root/"bad",payload={**LOOM,path:b"x"})
        link=self.root/"link";link.symlink_to(self.root/"real",target_is_directory=True)
        with self.assertRaises(ContractError): self.build(link)
        with self.assertRaises(ContractError):
            build_wheel("theme-forge-stellar-loom","0.4.0",LOOM,{p:0o4755 for p in LOOM},
                output_dir=self.root/"mode",release_hash="a"*64,license_files=LICENSES)

    def test_content_identity_and_tampered_record(self):
        result=self.build(self.root,content_identity_sha256="b"*64)
        with zipfile.ZipFile(result.wheel_path) as wheel:
            prov=json.loads(wheel.read("theme_forge_stellar_loom/_rs9/provenance.json"))
            self.assertEqual(prov["content_identity_sha256"],"b"*64)
            entries={n:wheel.read(n) for n in wheel.namelist()}
        entries["theme_forge_stellar_loom/payload/package/bin/tfsl.js"]=b"changed"
        target=self.root/"tampered.whl"
        with zipfile.ZipFile(target,"w") as wheel:
            for n,b in entries.items(): wheel.writestr(n,b)
        self.assertFalse(inspect_wheel(target)["record_valid"])

        with zipfile.ZipFile(result.wheel_path) as wheel:
            entries={n:wheel.read(n) for n in wheel.namelist()}
        rec_text = entries["theme_forge_stellar_loom-0.4.0.dist-info/RECORD"].decode("utf-8")
        rec_text += "theme_forge_stellar_loom/phantom.py,sha256=xxx,123\n"
        entries["theme_forge_stellar_loom-0.4.0.dist-info/RECORD"] = rec_text.encode("utf-8")
        target_phantom = self.root / "phantom_record.whl"
        with zipfile.ZipFile(target_phantom, "w") as wheel:
            for n, b in entries.items(): wheel.writestr(n, b)
        self.assertFalse(inspect_wheel(target_phantom)["record_valid"])

    @unittest.skipUnless(shutil.which("node"),"Node required for actual fixture entrypoint execution")
    def test_actual_offline_install_run_uninstall(self):
        result=self.build(self.root/"wheel")
        venv=self.root/"venv"
        subprocess.run([sys.executable,"-m","venv",str(venv)],check=True,capture_output=True,timeout=60)
        python=venv/"bin/python"
        env={**os.environ,"PIP_CONFIG_FILE":os.devnull,"PIP_NO_INDEX":"1","PIP_DISABLE_PIP_VERSION_CHECK":"1"}
        subprocess.run([str(python),"-m","pip","install","--no-index","--no-deps",str(result.wheel_path)],
            check=True,capture_output=True,env=env,timeout=30)
        cmd=subprocess.run([str(venv/"bin/tfsl")],capture_output=True,text=True,timeout=15)
        self.assertEqual(cmd.returncode,0); self.assertIn("synthetic-loom 0.4.0",cmd.stdout)
        batch=subprocess.run([str(venv/"bin/tfsl-batch")],input="",capture_output=True,text=True,timeout=15)
        self.assertEqual(batch.returncode,1); self.assertEqual(json.loads(batch.stdout)["error"]["code"],"EMPTY_INPUT")
        subprocess.run([str(python),"-m","pip","uninstall","-y","theme-forge-stellar-loom"],
            check=True,capture_output=True,env=env,timeout=30)
        self.assertFalse((venv/"bin/tfsl").exists())
        self.assertFalse((venv/"bin/tfsl-batch").exists())
        self.assertFalse(any(venv.glob("lib/python*/site-packages/theme_forge_stellar_loom*")))
