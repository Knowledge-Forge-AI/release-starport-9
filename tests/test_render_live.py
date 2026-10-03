"""Native recipe boundaries with actual core authentication of synthetic bytes."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.profiles import selection_for_intent
from rs9.release_core import authenticate_release, digest
from rs9.render_live import render_live
from rs9.scratch import canonical
from tests.release_fixtures import package_evidence
from tests.shadow_fixtures import fixture_evidence, tar_bytes
import tarfile


def cli_capture(root, product="theme-forge-stellar-loom"):
    root.mkdir()
    intent=package_evidence(root)
    intent["project"]["id"]=product
    intent["version"]="0.4.0" if product.endswith("loom") else "0.2.1"
    intent["tag"]="v"+intent["version"]
    intent["project"]["repository"]="Knowledge-Forge-AI/"+product
    intent["project"]["summary"]="Synthetic Theme Forge candidate"
    intent["license"]["expression"]="AGPL-3.0-or-later"
    commands={"tfsl":"bin/run.js", "tfsl-batch":"bin/batch.js"} if product.endswith("loom") else {"tfss":"bin/run.js"}
    intent["assets"][0]["commands"]={name:"package/"+path for name,path in commands.items()}
    intent["release"]["evidence"]["profile"]="npm-package-archive.v1alpha1"
    repo=intent["project"]["repository"]
    package=json.loads((root/"source/package.json").read_bytes())
    package.update(name="@knowledge-forge-ai/"+product, version=intent["version"], license="AGPL-3.0-or-later", bin=commands)
    source=canonical(package)
    (root/"source/package.json").write_bytes(source)
    tree_path=root/"api/tree.json";tree=json.loads(tree_path.read_bytes())
    tree["tree"][0]["sha"]=hashlib.sha1(b"blob "+str(len(source)).encode()+b"\0"+source).hexdigest()
    tree_path.write_bytes(canonical(tree))
    asset=intent["assets"][0]["name"]
    (root/"assets"/asset).write_bytes(tar_bytes([("package/package.json",source,0o644,tarfile.REGTYPE,""),
        *[("package/"+path,b"#!/usr/bin/env node\n",0o755,tarfile.REGTYPE,"") for path in commands.values()]]))
    (root/"assets/PROVENANCE.json").write_bytes(canonical({"release":{"repository":repo,"tag":intent["tag"],"tagTarget":"a"*40,"mergedMainTree":"b"*40}}))
    staged={p.name:p.read_bytes() for p in (root/"assets").iterdir() if p.name!="SHA256SUMS"}
    (root/"assets/SHA256SUMS").write_bytes("".join(digest(b)+"  "+name+"\n" for name,b in sorted(staged.items())).encode())
    paths=["api/repository.json","api/ref.json","api/release.json"]
    for relative in paths:
        p=root/relative;v=json.loads(p.read_bytes())
        if relative.endswith("repository.json"): v["full_name"]=repo
        if relative.endswith("ref.json"): v["ref"]="refs/tags/"+intent["tag"]
        if relative.endswith("release.json"):
            v["tag_name"]=intent["tag"]
            for row in v["assets"]:
                b=(root/"assets"/row["name"]).read_bytes()
                row.update(size=len(b),digest="sha256:"+digest(b))
        p.write_bytes(canonical(v))
    return authenticate_release(selection_for_intent(intent),root),intent


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve()

    def test_cli_local_staging_flags_and_architectures(self):
        capture,intent=cli_capture(self.root/"input")
        for adapter,arch,distro in (("pacman","x86_64","arch"),("rpm","x86_64","fedora-44"),
                                   ("rpm","aarch64","fedora-44")):
            dependency={"pacman":"nodejs>=22", "rpm":"nodejs >= 22", "apt":"nodejs (>= 22)"}[adapter]
            result=render_live(capture,intent,adapter=adapter,architecture=arch,dependencies=[dependency],distro=distro)
            files=result["rendered"]
            if adapter=="pacman":
                recipe=next(v for k,v in files.items() if k.endswith("PKGBUILD")).decode()
                self.assertIn("'!strip' '!debug'",recipe)
                self.assertIn('exec node "/usr/lib/theme-forge-stellar-loom/bin/run.js"',recipe)
            elif adapter=="rpm":
                recipe=next(v for k,v in files.items() if k.endswith(".spec")).decode()
                self.assertIn("ExclusiveArch: "+arch,recipe)
                self.assertIn("%global __os_install_post %{nil}",recipe)
                self.assertIn("%global _build_id_links none",recipe)
            staged=next(v for k,v in files.items() if k.endswith(".tgz"))
            self.assertEqual(digest(staged),capture.record["payloads"][0]["sha256"])
            self.assertEqual(result["status"],"unsigned-candidate")

    def test_missing_dependencies_forged_capture_changed_bytes_and_injection(self):
        capture,intent=cli_capture(self.root/"input")
        call=lambda c,d:render_live(c,intent,adapter="pacman",architecture="x86_64",dependencies=d,distro="arch")
        for deps in (None,[],["nodejs\nexecute"],["nodejs %()"],["not-a-runtime"],["nodejs"],["nodejs>=20"],["nodejs >= 22"]):
            with self.assertRaises(ContractError): call(capture,deps)
        with self.assertRaises(ContractError): call({"verdict":"authenticated"},["nodejs>=22"])
        capture.archives["package"].write_bytes(b"changed")
        with self.assertRaises(ContractError): call(capture,["nodejs>=22"])

    def test_nebular_both_native_architectures_and_released_launcher(self):
        evidence=self.root/"native";evidence.mkdir()
        intent=fixture_evidence(evidence)
        capture=authenticate_release(selection_for_intent(intent),evidence)
        for adapter,arch,distro in (("pacman","x86_64","arch"),("rpm","aarch64","fedora-44")):
            result=render_live(capture,intent,adapter=adapter,architecture=arch,dependencies=["synthetic-lib"],distro=distro)
            files=result["rendered"]
            if adapter in {"pacman","rpm"}:
                recipe=next(v for k,v in files.items() if k.endswith(("PKGBUILD",".spec"))).decode()
                self.assertIn("/usr/lib/theme-forge-nebular-fusion/bin/tfnf",recipe)
            self.assertTrue(any(k.endswith(".desktop") for k in files))
            self.assertTrue(any(k.endswith("icon.png") for k in files))
        with self.assertRaises(ContractError):
            render_live(capture,intent,adapter="pacman",architecture="aarch64",dependencies=["lib"],distro="arch")

    def test_distro_selection_and_burst_withheld(self):
        capture,intent=cli_capture(self.root/"input")
        with self.assertRaises(ContractError):
            render_live(capture,intent,adapter="apt",architecture="amd64",dependencies=["nodejs"],distro="debian-13")
        intent["version"]="0.4.1"
        with self.assertRaises(ContractError):
            render_live(capture,intent,adapter="pacman",architecture="x86_64",dependencies=["nodejs"],distro="arch")

    def test_apt_recipes_are_withheld_without_qualified_native_builder(self):
        capture,intent=cli_capture(self.root/"input_deb")
        for architecture in ("amd64", "arm64"):
            output = self.root / architecture
            output.mkdir()
            with self.subTest(architecture=architecture), self.assertRaises(ContractError) as caught:
                render_live(capture,intent,output,adapter="apt",architecture=architecture,
                            dependencies=["nodejs (>= 22)"],distro="ubuntu-26.04")
            self.assertEqual(caught.exception.code, "APT_RECIPE_UNQUALIFIED")
            self.assertEqual(list(output.iterdir()), [])
