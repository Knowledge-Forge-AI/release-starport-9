"""Synthetic source and runtime-pin admission for the single universal wheel."""
import json
from pathlib import Path
import unittest

from rs9 import nebular070_universal_consumer as universal
from rs9.errors import ContractError
from rs9.wheel import format_record
from rs9.wheel_nebular070_universal import _archive, DIST_INFO, PACKAGE
import tests.test_wheel_nebular070_universal as fixtures


class UniversalWheelAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.UniversalWheelTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        result = self.fixture.build()
        self.raw = (self.fixture.root / "out" / result["filename"]).read_bytes()
        self.repository = Path(__file__).resolve().parents[1]
        self.inputs = self.fixture.spec.read_bytes()

    def inspect(self, raw=None, inputs=None):
        return universal.inspect_universal_wheel(
            self.raw if raw is None else raw,
            self.inputs if inputs is None else inputs,
            repository=self.repository, legal_root=self.fixture.legal,
            description=self.fixture.description.read_bytes())

    def rewrite(self, mutate):
        import io
        import zipfile
        with zipfile.ZipFile(io.BytesIO(self.raw)) as archive:
            entries = {name: archive.read(name) for name in archive.namelist()}
        mutate(entries)
        entries.pop(DIST_INFO + "/RECORD")
        entries[DIST_INFO + "/RECORD"] = format_record(entries, DIST_INFO)
        return _archive(entries)

    def test_complete_source_only_wheel_is_bound_to_all_three_runtime_pins(self):
        checked = self.inspect()
        self.assertEqual(checked["wheel"]["tag"], "py3-none-any")
        self.assertEqual(set(checked["manifests"]), set(self.fixture.inputs["targets"]))
        self.assertFalse(checked["publication_admitted"])

    def test_platform_tag_or_embedded_archive_is_refused(self):
        for mutate in (
            lambda e: e.update({DIST_INFO + "/WHEEL": e[DIST_INFO + "/WHEEL"].replace(
                b"py3-none-any", b"py3-none-linux_x86_64")}),
            lambda e: e.update({PACKAGE + "/payload/native.tar.gz": b"native payload"}),
        ):
            with self.subTest(mutation=mutate), self.assertRaises(ContractError):
                self.inspect(self.rewrite(mutate))

    def test_changed_source_helper_description_or_manifest_is_refused(self):
        for name in (PACKAGE + "/launcher.py", PACKAGE + "/_fetch.py",
                     PACKAGE + "/_isolated/rs9/materialize.py",
                     DIST_INFO + "/METADATA", PACKAGE + "/runtimes/linux-x64-gnu.json"):
            with self.subTest(member=name), self.assertRaises(ContractError):
                self.inspect(self.rewrite(lambda e: e.update({name: e[name] + b"\n"})))

    def test_pin_relabel_or_publication_flag_cannot_create_authority(self):
        value = json.loads(self.inputs)
        value["targets"]["linux-x64-gnu"]["asset"]["sha256"] = "0" * 64
        with self.assertRaises(ContractError):
            self.inspect(inputs=json.dumps(value).encode())
        name = PACKAGE + "/_rs9/provenance.json"
        def mutate(entries):
            value = json.loads(entries[name])
            value["builder_can_publish"] = True
            entries[name] = json.dumps(value).encode()
        with self.assertRaises(ContractError):
            self.inspect(self.rewrite(mutate))
