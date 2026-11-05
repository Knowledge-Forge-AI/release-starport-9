"""Real Pages scanner and assembly retain the current ARM namespace boundary."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.errors import ContractError
from rs9.pages import (CATEGORY_CANDIDATE_ASSET, CATEGORY_INDEX,
                       classify_pages_path, scan_pages_tree, validate_pages_tree)
from rs9.pages_candidate import (assemble_pages_candidate, collect_candidate_sources,
                                 exact_inventory_for)


class CurrentPagesScannerTests(unittest.TestCase):
    metadata = ("rs9.db", "rs9.db.tar.gz", "rs9.db.sig", "rs9.db.tar.gz.sig",
                "rs9.files", "rs9.files.tar.gz", "rs9.files.sig", "rs9.files.tar.gz.sig")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_current_pacman_assets_and_index_in_both_exact_architectures(self):
        for arch in ("x86_64", "aarch64"):
            for name in (*self.metadata, "example-1-1-aarch64.pkg.tar.zst",
                         "example-1-1-any.pkg.tar.zst.sig"):
                with self.subTest(arch=arch, name=name):
                    self.assertEqual(classify_pages_path("pacman/"+arch+"/"+name,
                        qualification_generation=CURRENT_GENERATION),
                        (True, CATEGORY_CANDIDATE_ASSET))
            self.assertEqual(classify_pages_path("pacman/"+arch+"/index.html",
                qualification_generation=CURRENT_GENERATION), (True, CATEGORY_INDEX))

    def test_historical_default_and_explicit_selection_still_reject_arm(self):
        for name in (*self.metadata, "index.html", "example-1-1-aarch64.pkg.tar.zst"):
            path = "pacman/aarch64/"+name
            self.assertEqual(classify_pages_path(path), (False, ""))
            self.assertEqual(classify_pages_path(path,
                qualification_generation=HISTORICAL_GENERATION), (False, ""))

    def test_current_selection_does_not_broaden_roots_depth_arch_or_suffix(self):
        for path in ("pacman/arm64/rs9.db", "pacman/aarch64/nested/rs9.db",
                     "pacman/aarch64/.rs9.db", "pacman/.aarch64/rs9.db",
                     "pacman/aarch64/private-key.db", "pacman/aarch64/leak.sig",
                     "pacman/aarch64/rs9.db.txt", "pacman/aarch64/rs9.db.sig.old",
                     "other/aarch64/rs9.db", "pacman/aarch64/other/index.html"):
            with self.subTest(path=path):
                self.assertEqual(classify_pages_path(path,
                    qualification_generation=CURRENT_GENERATION), (False, ""))

    def test_real_scan_and_assembly_bind_both_views_and_signature_path(self):
        # Inert public metadata tests scanner/custody behavior, not cryptography.
        files = {"pacman/"+arch+"/"+name: b"inert public metadata"
                 for arch in ("x86_64", "aarch64") for name in self.metadata}
        sources = collect_candidate_sources(files=files)
        inventory = exact_inventory_for(sources)
        candidate = assemble_pages_candidate(self.root, files=files,
            exact_inventory=inventory, qualification_generation=CURRENT_GENERATION)
        self.assertEqual(candidate.exact_inventory, inventory)
        record = validate_pages_tree(self.root, manifest=inventory,
            qualification_generation=CURRENT_GENERATION)
        self.assertEqual(record.to_dict()["file_count"], len(inventory))
        self.assertEqual((self.root/"pacman/aarch64/rs9.files.tar.gz.sig").read_bytes(),
                         files["pacman/aarch64/rs9.files.tar.gz.sig"])
        with self.assertRaises(ContractError) as caught:
            validate_pages_tree(self.root, manifest=inventory)
        self.assertEqual(caught.exception.code, "DISALLOWED_FILE")

    def _signature(self, contents=b"inert public signature"):
        path = self.root/"pacman/aarch64/rs9.files.tar.gz.sig"
        path.parent.mkdir(parents=True)
        path.write_bytes(contents)
        return path, {path.relative_to(self.root).as_posix(): hashlib.sha256(contents).hexdigest()}

    def test_current_scan_keeps_exact_manifest_and_tamper_rejection(self):
        path, inventory = self._signature()
        validate_pages_tree(self.root, manifest=inventory,
            qualification_generation=CURRENT_GENERATION)
        path.write_bytes(b"modified public signature")
        with self.assertRaises(ContractError) as caught:
            validate_pages_tree(self.root, manifest=inventory,
                qualification_generation=CURRENT_GENERATION)
        self.assertEqual(caught.exception.code, "TAMPER_DETECTED")
        with self.assertRaises(ContractError) as caught:
            validate_pages_tree(self.root, manifest={},
                qualification_generation=CURRENT_GENERATION)
        self.assertEqual(caught.exception.code, "UNMANIFESTED_FILE")

    def test_current_scan_keeps_secret_packet_rejection(self):
        self._signature(bytes([0xC5, 2, 4, 0]))
        with self.assertRaises(ContractError) as caught:
            scan_pages_tree(self.root, qualification_generation=CURRENT_GENERATION)
        self.assertEqual(caught.exception.code, "CREDENTIAL_DETECTED")

    def test_current_scan_keeps_leaf_symlink_rejection(self):
        path, inventory = self._signature()
        with tempfile.TemporaryDirectory() as other:
            outside = Path(other)/"public-signature.txt"
            outside.write_bytes(path.read_bytes())
            path.unlink()
            path.symlink_to(outside)
            with self.assertRaises(ContractError) as caught:
                validate_pages_tree(self.root, manifest=inventory,
                    qualification_generation=CURRENT_GENERATION)
            self.assertEqual(caught.exception.code, "SYMLINK_REJECTED")

    def test_unknown_selection_refuses_before_assembly_writes(self):
        for fn, args, kwargs in (
            (classify_pages_path, ("pacman/aarch64/rs9.db",), {}),
            (scan_pages_tree, (self.root,), {}),
            (validate_pages_tree, (self.root,), {"manifest": {}}),
            (assemble_pages_candidate, (self.root,), {"files": {}, "exact_inventory": {}}),
        ):
            with self.subTest(function=fn.__name__), self.assertRaises(ContractError) as caught:
                fn(*args, **kwargs, qualification_generation="unreviewed")
            self.assertEqual(caught.exception.code, "GENERATION_SELECTION")
            self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
