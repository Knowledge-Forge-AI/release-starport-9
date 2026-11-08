"""Bounded scans of the exact public NativeRC evidence fixture."""

import io
import json
from pathlib import Path
import re
import tarfile
import tempfile
import unittest


PROJECT_SOURCE = Path(__file__).resolve().parents[1]
from tests import test_hygiene as hygiene



class NativeFixtureHygieneTests(unittest.TestCase):
    archive_relative = hygiene.NATIVE_ARCHIVE_RELATIVE
    inventory_relative = hygiene.NATIVE_INVENTORY_RELATIVE
    source_archive = PROJECT_SOURCE / archive_relative
    source_inventory = PROJECT_SOURCE / inventory_relative
    private_path = re.compile(
        r"/" + r"Users/|/" + r"home/[^/\s]+/|[A-Z]:\\" + r"Users\\"
    )

    def test_exact_capsule_decodes_and_scans_all_rows(self):
        texts = hygiene.file_texts(
            self.source_archive, PROJECT_SOURCE, {}, public_inputs={}
        )
        self.assertEqual(len(texts), hygiene.NATIVE_MEMBER_COUNT)
        self.assertTrue(any(name.endswith(":rc-index.json") for name, _ in texts))
        allowance_count = sum(
            hygiene._native_public_path_allowance(name, text, self.private_path)
            for name, text in texts
        )
        self.assertEqual(allowance_count, 5)
        for name, text in texts:
            hygiene.scan_file_text(name, text, private_path=self.private_path)

    def test_changed_archive_or_inventory_never_falls_back_to_generic_text(self):
        archive_bytes = self.source_archive.read_bytes()
        inventory_bytes = self.source_inventory.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive = root / self.archive_relative
            inventory = root / self.inventory_relative
            archive.parent.mkdir(parents=True)
            archive.write_bytes(archive_bytes[:-1] + bytes([archive_bytes[-1] ^ 1]))
            inventory.write_bytes(inventory_bytes)
            archive.chmod(0o644)
            inventory.chmod(0o644)
            with self.assertRaises(ValueError):
                hygiene.file_texts(archive, root, {}, public_inputs={})

            archive.write_bytes(archive_bytes)
            inventory.write_bytes(inventory_bytes[:-1] + bytes([inventory_bytes[-1] ^ 1]))
            with self.assertRaises(ValueError):
                hygiene.file_texts(archive, root, {}, public_inputs={})

            inventory.unlink()
            with self.assertRaises(ValueError):
                hygiene.file_texts(archive, root, {}, public_inputs={})

            renamed = root / "tests/fixtures/unlisted-native-evidence.tar.gz"
            renamed.write_bytes(archive_bytes)
            with self.assertRaises(ValueError):
                hygiene.file_texts(renamed, root, {}, public_inputs={})

    def test_exact_public_path_classification_does_not_allow_new_path(self):
        texts = hygiene.file_texts(
            self.source_archive, PROJECT_SOURCE, {}, public_inputs={}
        )
        target_name, target_text = next(
            (name, text)
            for name, text in texts
            if "darwin-arm64-A-npm-package.receipt" in name
        )
        with self.assertRaises(ValueError):
            hygiene.scan_file_text(
                target_name,
                target_text.rstrip()[:-1]
                + ',"unlisted":"/' + "Users/synthetic/unlisted" + '"}\n',
                private_path=self.private_path,
            )

    def test_modified_member_cannot_borrow_known_path_classification(self):
        texts = hygiene.file_texts(self.source_archive, PROJECT_SOURCE, {}, public_inputs={})
        name, text = next((name, text) for name, text in texts
                          if "darwin-arm64-A-npm-package.receipt" in name)
        value = json.loads(text)
        public_value = value["executable"]["path"]
        value["unlisted"] = "/" + "Users/synthetic/unlisted"
        forged = json.dumps(value).replace(json.dumps(public_value),
                                           json.dumps(public_value).replace("/", "\\/"), 1)
        with self.assertRaisesRegex(ValueError, "member pin mismatch"):
            hygiene.scan_file_text(name, forged, private_path=self.private_path)

    def test_nested_index_is_pinned_and_rejects_changed_bytes(self):
        texts = hygiene.file_texts(
            self.source_archive, PROJECT_SOURCE, {}, public_inputs={}
        )
        nested = next(text for name, text in texts if name.endswith(":rc-index.json"))
        self.assertEqual(len(nested.encode()), hygiene.NATIVE_INDEX_JSON_BYTES)
        with tarfile.open(fileobj=io.BytesIO(self.source_archive.read_bytes()), mode="r:gz") as archive:
            nested_bytes = archive.extractfile(archive.getmember(hygiene.NATIVE_INDEX_MEMBER)).read()
        with self.assertRaises(ValueError):
            hygiene._native_index_text(nested_bytes[:-1] + bytes([nested_bytes[-1] ^ 1]))

    def test_existing_scan_contract_runs_on_archive_and_inventory(self):
        for path in (self.source_archive, self.source_inventory):
            for name, text in hygiene.file_texts(
                path, PROJECT_SOURCE, {}, public_inputs={}
            ):
                with self.subTest(member=name):
                    hygiene.scan_file_text(name, text, private_path=self.private_path)


if __name__ == "__main__":
    unittest.main()
