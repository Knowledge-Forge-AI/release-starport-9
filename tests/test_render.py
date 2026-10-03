import copy
from pathlib import Path
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.ingestion import authenticate_shadow as authenticate
from rs9.render import desktop_entry, nix_string, rpm_string, render
from rs9.scratch import ConfinedWriter
from tests.shadow_fixtures import fixture_evidence


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        evidence = self.root / "evidence"
        evidence.mkdir()
        self.n = fixture_evidence(evidence)
        self.auth = authenticate(self.n, evidence)

    def output(self, name="output"):
        output = self.root / name
        output.mkdir()
        return output

    def test_double_render_determinism_and_deferred_fixture(self):
        a, b = self.output("a"), self.output("b")
        manifest = render(self.auth, a)
        self.assertEqual(manifest, render(self.auth, b))
        self.assertEqual(manifest["verdict"], "deferred")
        self.assertEqual(manifest["license_authority"], "consistent")
        for entry in manifest["files"]:
            self.assertEqual((a / entry["path"]).read_bytes(), (b / entry["path"]).read_bytes())
        self.assertIn("dontFixup = true", (a / "nix/theme-forge-nebular-fusion.nix").read_text())
        self.assertIn("sha256sum -c -", (a / "rpm/theme-forge-nebular-fusion.spec").read_text())
        self.assertIn("bin/tfnf", (a / "pacman/theme-forge-nebular-fusion/PKGBUILD").read_text())

    def test_saved_record_cannot_authorize_render(self):
        forged = {**self.auth.record, "authentication": {"status": "authenticated"}}
        with self.assertRaises(ContractError) as caught:
            render(forged, self.output())
        self.assertEqual(caught.exception.code, "AUTHENTICATION_REQUIRED")

    def test_unresolved_intent_blocks_even_consistent_license_evidence(self):
        self.auth.normalized["license"]["status"] = "unresolved"
        manifest = render(self.auth, self.output())
        self.assertEqual(manifest["license_authority"], "consistent")
        self.assertEqual(manifest["license_intent_status"], "unresolved")
        self.assertIn("tenant-license-unresolved", manifest["blockers"])
        self.assertEqual(manifest["verdict"], "deferred")

    def test_invalid_license_status_rejected_before_output(self):
        self.auth.normalized["license"]["status"] = "accepted"
        output = self.output()
        with self.assertRaises(ContractError):
            render(self.auth, output)
        self.assertEqual(list(output.iterdir()), [])

    def test_per_adapter_unsafe_values_rejected_before_writes(self):
        for adapter in ("nix", "pacman", "dnf"):
            for unsafe in ("a'quote", "a$HOME", "a`id`", "a%macro", "a${expr}", "a\nline", "../escape"):
                with self.subTest(adapter=adapter, unsafe=unsafe):
                    auth = copy.copy(self.auth)
                    auth.normalized = copy.deepcopy(self.n)
                    target = next(t for t in auth.normalized["targets"] if t["adapter"] == adapter)
                    target["name"] = unsafe
                    output = self.output("bad-" + str(len(list(self.root.iterdir()))))
                    with self.assertRaises(ContractError):
                        render(auth, output)
                    self.assertEqual(list(output.iterdir()), [])

    def test_text_escaping_and_desktop_no_extra_unbound_keys(self):
        self.assertEqual(nix_string('A "name" ${literal}'), '"A \\"name\\" \\${literal}"')
        self.assertEqual(rpm_string("100% literal"), "100%% literal")
        self.n["project"]["name"] = "Literal\\Name"
        text = desktop_entry(self.n).decode()
        self.assertIn("Literal\\\\Name", text)
        self.assertNotIn("MimeType", text)
        self.assertNotIn("%U", text)

    def test_output_root_symlinks_and_existing_contents(self):
        target = self.output("target")
        alias = self.root / "alias"
        alias.symlink_to(target, target_is_directory=True)
        with self.assertRaises(ContractError):
            render(self.auth, alias)
        (target / "keep").write_text("unrelated")
        with self.assertRaises(ContractError):
            render(self.auth, target)
        self.assertEqual((target / "keep").read_text(), "unrelated")

    def test_inner_symlink_traversal_and_exclusive_writes(self):
        output = self.output()
        external = self.output("external")
        with ConfinedWriter(output) as writer:
            (output / "inside").symlink_to(external, target_is_directory=True)
            with self.assertRaises(ContractError):
                writer.write("inside/escape", b"x")
            with self.assertRaises(ContractError):
                writer.write("../escape", b"x")
            writer.write("normal", b"first")
            with self.assertRaises(ContractError):
                writer.write("normal", b"second")
        self.assertEqual(list(external.iterdir()), [])
        self.assertEqual((output / "normal").read_bytes(), b"first")

    def test_asset_changed_revision_and_license_rejected(self):
        with self.assertRaises(ContractError):
            render(self.auth, self.output("revision"), revision=True)
        self.auth.normalized["license"]["expression"] = "Commercial"
        with self.assertRaises(ContractError):
            render(self.auth, self.output("license"))
        self.auth.normalized["license"]["expression"] = "AGPL-3.0-or-later"
        path = next(iter(self.auth.archives.values()))
        path.write_bytes(b"changed")
        with self.assertRaises(ContractError) as caught:
            render(self.auth, self.output("changed"))
        self.assertEqual(caught.exception.code, "INPUT_CHANGED")
