"""Production index byte binding, using in-memory path records only."""
import ast
from pathlib import Path, PurePosixPath
import unittest
from unittest.mock import patch

from rs9 import apt_diagnostics as ad


class MemoryPath:
    nodes = {}

    def __init__(self, path):
        self.path = PurePosixPath(path)

    @property
    def name(self):
        return self.path.name

    @property
    def suffix(self):
        return self.path.suffix

    def is_file(self):
        return str(self.path) in self.nodes

    def is_symlink(self):
        return self.nodes.get(str(self.path), {}).get("symlink", False)

    def rglob(self, pattern):
        prefix = str(self.path) + "/"
        return [MemoryPath(p) for p in self.nodes if p.startswith(prefix)]

    def relative_to(self, other):
        return self.path.relative_to(other.path)

    def read_bytes(self):
        return self.nodes[str(self.path)]["data"]

    def __lt__(self, other):
        return str(self.path) < str(other.path)


class ProductionTrustIdentityTests(unittest.TestCase):
    def setUp(self):
        self.spec = {"family": "pacman", "mounts": [("/input/arch", "/srv/rs9/pacman", False)],
                     "configure": [["public-config", "knowledge-forge-ai"]], "refresh": ["pacman", "-Sy"]}
        MemoryPath.nodes = {}
        self.mock_path = patch.object(ad, "Path", MemoryPath)
        self.mock_path.start()
        self.addCleanup(self.mock_path.stop)

    def put(self, name, data=b"public index fixture", **kwargs):
        MemoryPath.nodes["/input/arch/" + name] = {"data": data, **kwargs}

    def identity(self):
        return ad.trust_identity(self.spec)

    def test_production_database_and_signature_bytes_bound_in_both_architectures(self):
        for arch in ("x86_64", "aarch64"):
            for suffix in (".db", ".db.sig", ".db.tar.gz", ".db.tar.gz.sig"):
                with self.subTest(arch=arch, suffix=suffix):
                    MemoryPath.nodes = {}
                    name = arch + "/knowledge-forge-ai" + suffix
                    self.put(name)
                    before = self.identity()
                    self.put(name, b"changed public index fixture")
                    self.assertNotEqual(self.identity(), before)

    def test_missing_production_database_changes_identity(self):
        self.put("aarch64/knowledge-forge-ai.db")
        before = self.identity()
        MemoryPath.nodes.clear()
        self.assertNotEqual(self.identity(), before)

    def test_architecture_path_is_bound_even_when_bytes_identical(self):
        self.put("aarch64/knowledge-forge-ai.db")
        before = self.identity()
        MemoryPath.nodes.clear()
        self.put("x86_64/knowledge-forge-ai.db")
        self.assertNotEqual(self.identity(), before)

    def test_historical_identity_is_byte_identical_to_original_function(self):
        # Remove only the added literal set entries from the actual AST to
        # reconstruct the previous function; all other code remains identical.
        function = next(n for n in ast.parse(Path(ad.__file__).read_text()).body
                        if isinstance(n, ast.FunctionDef) and n.name == "trust_identity")
        added = {"knowledge-forge-ai.db", "knowledge-forge-ai.db.sig",
                 "knowledge-forge-ai.db.tar.gz", "knowledge-forge-ai.db.tar.gz.sig"}
        for node in ast.walk(function):
            if isinstance(node, ast.Set):
                node.elts = [e for e in node.elts if not (isinstance(e, ast.Constant) and e.value in added)]
        module = ast.Module(body=[function], type_ignores=[])
        namespace = {"Path": MemoryPath}
        exec(compile(ast.fix_missing_locations(module), "<original-trust-function>", "exec"), namespace)
        original = namespace["trust_identity"]
        for name in ("rs9.db", "rs9.db.sig", "rs9.db.tar.gz", "rs9.db.tar.gz.sig",
                     "InRelease", "Release", "Release.gpg", "repomd.xml", "repomd.xml.asc", "fixture.asc"):
            with self.subTest(name=name):
                MemoryPath.nodes = {}
                self.put("x86_64/" + name)
                self.assertEqual(self.identity(), original(self.spec))

    def test_symlink_leaves_and_writable_mounts_keep_existing_exclusion(self):
        before = self.identity()
        self.put("x86_64/knowledge-forge-ai.db", symlink=True)
        self.assertEqual(self.identity(), before)
        MemoryPath.nodes.clear()
        self.spec["mounts"] = [("/input/arch", "/srv/rs9/pacman", True)]
        before = self.identity()
        self.put("aarch64/knowledge-forge-ai.db")
        self.assertEqual(self.identity(), before)

    def test_public_key_and_configuration_still_bound(self):
        self.put("key.asc", b"public-key-fixture")
        before = self.identity()
        self.put("key.asc", b"changed-public-key-fixture")
        self.assertNotEqual(self.identity(), before)
        before = self.identity()
        self.spec["configure"] = [["changed-config"]]
        self.assertNotEqual(self.identity(), before)


if __name__ == "__main__":
    unittest.main()
