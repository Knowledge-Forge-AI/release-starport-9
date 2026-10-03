"""Opt-in reauthentication of captured live bytes; ordinary fixtures cannot pass."""
import json
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from rs9.contract import normalize
from rs9.compare import parse_srcinfo, reference_facts
from rs9.dependencies import derive_dependencies
from rs9.ingestion import authenticate_shadow as authenticate
from rs9.ingestion import read_evidence, digest
from rs9.render import render
from rs9.scratch import canonical
from rs9.gates import derive_gates
from rs9.planner import adapter_outputs_from_shadow, destination_policy, plan
from tests.publication_fixtures import observation, T0

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("RS9_NEBULAR_EVIDENCE_DIR"), "live capture directory not supplied")
class LiveNebularTests(unittest.TestCase):
    def test_captured_release_bytes_and_deterministic_goldens(self):
        normalized = json.loads(normalize(ROOT / "examples/theme-forge/theme-forge-nebular-fusion", ROOT / "examples/destinations.example.toml", "0.6.1"))
        auth = authenticate(normalized, os.environ["RS9_NEBULAR_EVIDENCE_DIR"])
        fixture = ROOT / "tests/fixtures/nebular-0.6.1"
        self.assertEqual(canonical(auth.record), (fixture / "ingestion.json").read_bytes())
        self.assertEqual(canonical(derive_dependencies(auth)), (fixture / "dependency-evidence.json").read_bytes())
        with tempfile.TemporaryDirectory() as tmp:
            manifest = render(auth, Path(tmp).resolve())
            golden = ROOT / "tests/golden/shadow/nebular-0.6.1"
            self.assertEqual(canonical(manifest), (golden / "render-manifest.json").read_bytes())
            for row in manifest["files"]:
                self.assertEqual((Path(tmp) / row["path"]).read_bytes(), (golden / row["path"]).read_bytes())
            output = next(row for row in adapter_outputs_from_shadow(auth, manifest) if row["destination"]["mode"] == "direct")
            gates = derive_gates(normalized, auth.release_capture, auth.profile_result, output)
            license_gate = next(row for row in gates if row["id"] == "license.authority")
            self.assertEqual(license_gate["status"], "fail")
            candidate = plan(normalized, auth.release_capture, auth.profile_result, output, gates,
                             destination_policy(), observation(output), evaluated_at=T0, ingestion_record=auth.record)
            self.assertEqual(candidate["outcome"], "block-gate")
            self.assertIn("tenant-license-conflict", candidate["reasons"])

    def test_captured_reference_tree_and_byte_comparison(self):
        evidence = Path(os.environ["RS9_NEBULAR_EVIDENCE_DIR"])
        fixture = ROOT / "tests/fixtures/nebular-0.6.1"
        reference = json.loads((fixture / "reference-facts.json").read_bytes())
        commit = json.loads(read_evidence(evidence, "api/ref-packages-main.json"))
        tree = json.loads(read_evidence(evidence, "api/ref-tree-" + reference["tree"] + ".json"))
        self.assertEqual(commit["sha"], reference["commit"])
        self.assertEqual(commit["commit"]["tree"]["sha"], tree["sha"])
        self.assertIs(tree["truncated"], False)
        blobs = {r["path"]: r["sha"] for r in tree["tree"] if r["type"] == "blob"}
        for path, row in reference["files"].items():
            data = read_evidence(evidence, "reference/" + path)
            self.assertEqual(digest(data), row["sha256"])
            self.assertEqual(hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest(), blobs[path])
            self.assertEqual(blobs[path], row["git_blob_sha"])
        self.assertEqual(reference_facts(evidence / "reference"), reference["facts"])
        srcinfo = parse_srcinfo(read_evidence(evidence, "reference/aur/theme-forge-nebular-fusion-bin/.SRCINFO"))
        aur = reference["facts"]["aur"]
        for key, field in (("pkgname", "name"), ("pkgver", "version"), ("license", "license")):
            self.assertEqual(srcinfo[key], [aur[field]])
        self.assertEqual(sorted(srcinfo["arch"]), aur["architectures"])
        self.assertEqual(srcinfo["provides"], aur["provides"])
        self.assertEqual(srcinfo["conflicts"], aur["conflicts"])
        for arch in aur["architectures"]:
            self.assertEqual(sorted(srcinfo["depends"] + srcinfo.get("depends_" + arch, [])), aur["dependencies"][arch])
        comparison = json.loads((fixture / "reference-byte-comparison.json").read_bytes())
        for row in comparison["files"]:
            before = read_evidence(evidence, "reference/" + row["reference_path"])
            after = ((ROOT / "tests/golden/shadow/nebular-0.6.1" / row["shadow_path"]).read_bytes()
                     if "shadow_path" in row else read_evidence(evidence, "source/" + row["shadow_authority"].partition(":")[2]))
            self.assertEqual(digest(before), row["reference_sha256"])
            self.assertEqual(digest(after), row["shadow_sha256"])
            self.assertEqual(before == after, row["byte_equal"])

    def test_reference_semantic_facts_detect_material_recipe_drift(self):
        evidence = Path(os.environ["RS9_NEBULAR_EVIDENCE_DIR"])
        fixture = ROOT / "tests/fixtures/nebular-0.6.1"
        reference = json.loads((fixture / "reference-facts.json").read_bytes())
        changes = [
            ("templates/pacman/theme-forge-nebular-fusion/PKGBUILD", "'gtk3'", "'changed-gtk'", "pacman", "dependencies"),
            ("templates/rpm/theme-forge-nebular-fusion.spec", "Requires:       gtk3", "Requires:       changed-gtk", "rpm", "dependencies"),
            ("aur/theme-forge-nebular-fusion-bin/PKGBUILD", "provides=('theme-forge-nebular-fusion')", "provides=('changed-provider')", "aur", "provides"),
            ("templates/desktop/theme-forge-nebular-fusion.desktop", "Exec=tfnf %U", "Exec=changed-launcher %U", "desktop", "Exec"),
            ("templates/pacman/theme-forge-nebular-fusion/PKGBUILD", "/usr/bin/tfnf", "/usr/bin/changed-launcher", "pacman", "installed_paths"),
            ("packages/nebular-fusion.nix", 'name = "tfnf";', 'name = "changed-fhs";', "nix", "name"),
        ]
        for relative, old, new, adapter, field in changes:
            with self.subTest(adapter=adapter, field=field), tempfile.TemporaryDirectory() as temp:
                copy = Path(temp)
                for path in reference["files"]:
                    if path.endswith(".png"):
                        continue
                    target = copy / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(read_evidence(evidence, "reference/" + path))
                target = copy / relative
                text = target.read_text()
                self.assertIn(old, text)
                target.write_text(text.replace(old, new))
                self.assertNotEqual(reference_facts(copy)[adapter][field], reference["facts"][adapter][field])
