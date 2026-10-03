from pathlib import Path
import tarfile
import tempfile
import unittest

from rs9.dependencies import derive_dependencies, shebang
from rs9.ingestion import authenticate
from rs9.scratch import canonical
from tests.elf_builder import build_elf
from tests.shadow_fixtures import fixture_evidence


class DependencyTests(unittest.TestCase):
    def derive(self, extra=()):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            normalized = fixture_evidence(root, extra_linux=extra)
            auth = authenticate(normalized, root)
            before = derive_dependencies(auth)
            self.assertEqual(canonical(before), canonical(derive_dependencies(auth)))
            return before

    def test_both_architectures_versions_and_interpreter(self):
        evidence = self.derive()
        self.assertEqual(set(evidence["platforms"]), {"aarch64-linux", "x86_64-linux"})
        for value in evidence["platforms"].values():
            self.assertEqual(value["version_floors"]["GLIBC"], "2.34")
            self.assertEqual(value["packages"]["arch"], ["bash", "glibc"])
            self.assertIn("not-executed", value["mapping_qualification"])

    def test_bundled_requires_loader_search_evidence(self):
        root = "theme-forge-nebular-fusion/lib/"
        extra = [(root + "consumer.so", build_elf(elf_type="shared", needed=["liblocal.so.1"], runpath=["$ORIGIN"]), 0o644, tarfile.REGTYPE, ""),
                 (root + "liblocal.so.1", build_elf(elf_type="shared", soname="liblocal.so.1"), 0o644, tarfile.REGTYPE, "")]
        evidence = self.derive(extra)
        value = evidence["platforms"]["x86_64-linux"]
        self.assertEqual(value["bundled"][0]["soname"], "liblocal.so.1")
        self.assertNotIn("liblocal.so.1", [r["soname"] for r in value["system_sonames"]])
        extra[0] = (root + "consumer.so", build_elf(elf_type="shared", needed=["liblocal.so.1"]), 0o644, tarfile.REGTYPE, "")
        value = self.derive(extra)["platforms"]["x86_64-linux"]
        self.assertIn({"reason": "unmapped-system-soname", "soname": "liblocal.so.1"}, value["unresolved"])

    def test_script_runtime_and_foreign_architecture_are_findings(self):
        extra = [("theme-forge-nebular-fusion/bin/tool.js", b"#!/usr/bin/env node\n", 0o755, tarfile.REGTYPE, ""),
                 ("theme-forge-nebular-fusion/lib/foreign.so", build_elf(machine="aarch64", elf_type="shared"), 0o644, tarfile.REGTYPE, "")]
        value = self.derive(extra)["platforms"]["x86_64-linux"]
        self.assertIn("nodejs", value["packages"]["arch"])
        self.assertIn("foreign-architecture", [r["reason"] for r in value["unresolved"]])
        self.assertIn("node-version-and-module-resolution-unqualified", [r["reason"] for r in value["unresolved"]])

    def test_shebang_indeterminate_env(self):
        self.assertIsNone(shebang(b"normal text"))
        self.assertEqual(shebang(b"#!/usr/bin/env -S node --flag\n")["interpreter"], "node")
        self.assertEqual(shebang(b"#!/usr/bin/env -i node\n")["resolution"], "unresolved-env")
