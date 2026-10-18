"""Exact first-wave identities and negative npm payload admission."""
import copy
import tempfile
from pathlib import Path
import unittest

from rs9.tf_pypi_archive import AdmissionError, canonical, fail, read_tar, sha256
from rs9.tf_pypi_backend import write_tar
from rs9.tf_pypi_model import (PRODUCTS, admit_bytes, intake, load_pin, pure_payload,
                              strict_json, validate_pin)
from tests.tf_pypi_fixtures import fixture


class ModelTests(unittest.TestCase):
    def error(self, code, function, *args):
        with self.assertRaises(AdmissionError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, "TF_PYPI_" + code)

    def test_frozen_pins_three_only_blocked(self):
        for product in PRODUCTS:
            pin = load_pin(product)
            self.assertIn(pin["source_status"], {"READY", "BLOCKED"})
            self.assertEqual(bool(pin["withheld"]), pin["source_status"] == "BLOCKED")
            self.assertEqual(validate_pin(pin), pin)
        self.error("PRODUCT", load_pin, "theme-forge-nebular-fusion")

    def test_each_synthetic_manifest_and_command_set_admitted(self):
        for project in PRODUCTS:
            pin, data = fixture(project)
            files = admit_bytes(pin, data, pin["asset"])
            self.assertTrue(all("package/" + p in files for p in pin["bins"].values()))

    def test_hash_size_and_basename_drift(self):
        pin, data = fixture()
        self.error("SIZE", admit_bytes, pin, data + b"x", pin["asset"])
        self.error("HASH", admit_bytes, pin, data[:-1] + bytes([data[-1] ^ 1]), pin["asset"])
        self.error("BASENAME", admit_bytes, pin, data, "other.tgz")

    def test_product_version_name_engine_license_and_bins(self):
        changes = [({"name": "@attacker/other"}, "NAME"), ({"version": "9.9.9"}, "VERSION"),
                   ({"engines": {"node": ">=20"}}, "NODE_ENGINE"),
                   ({"license": "MIT"}, "LICENSE"), ({"bin": {}}, "ENTRYPOINT"),
                   ({"bin": {"tfsl": "../outside.js"}}, "ENTRYPOINT")]
        for change, code in changes:
            with self.subTest(code=code):
                pin, data = fixture(changes=change)
                self.error(code, admit_bytes, pin, data, pin["asset"])

    def test_pin_cannot_change_project_version_or_workflow(self):
        pin = load_pin("theme-forge-solar-sail")
        for key, value in (("project", "other"), ("version", "1.0.0"),
                           ("workflow", "rs9-pypi-publish.yml"), ("asset", "other.tgz"),
                           ("npm_name", "theme-forge-solar-sail"), ("size", True)):
            bad = {**pin, key: value}
            self.error("PRODUCT" if key == "project" else "PIN", validate_pin, bad)

    def test_closed_pin_schema_and_dependency_identity(self):
        pin = load_pin("theme-forge-stellar-burst")
        self.error("PIN", validate_pin, {**pin, "unknown_authority": True})
        for field, value in (("name", "@attacker/xmldom"), ("version", "9.9.9"),
                             ("sha256", "0" * 64), ("url", "https://registry.example.invalid/x.tgz")):
            bad = copy.deepcopy(pin)
            bad["dependencies"][0][field] = value
            self.error("PIN", validate_pin, bad)

    def test_missing_or_downloading_entrypoint_refused(self):
        for extra in ({"bin/tfsl.js": (b"import('npm');", 0o644)},
                      {"bin/tfsl.js": (b"require('child_process').execSync('npx foo')", 0o644)}):
            pin, data = fixture(extra=extra)
            self.error("ENTRYPOINT", admit_bytes, pin, data, pin["asset"])
        pin, data = fixture()
        files = {p[len("package/"):]: value for p, value in read_tar(data).items()}
        files.pop("bin/tfsl.js")
        data = write_tar(files, "package")
        pin.update(size=len(data), sha256=sha256(data))
        self.error("ENTRYPOINT", admit_bytes, pin, data, pin["asset"])

    def test_dependency_confusion_platform_and_native_are_not_universal(self):
        for key, value in (("dependencies", {"foo": "^1"}), ("optionalDependencies", {"foo": "1.0.0"}),
                           ("peerDependencies", {"foo": "1"}), ("os", ["darwin"]),
                           ("cpu", ["arm64"]), ("bundledDependencies", ["foo"]), ("libc", ["glibc"])):
            pin, data = fixture(changes={key: value})
            files = admit_bytes(pin, data, pin["asset"])
            self.error("DEPENDENCY", pure_payload, files)
        for path, body in (("native/x.node", b"addon"), ("data.bin", b"\x7fELF"),
                           ("data.bin", b"\xcf\xfa\xed\xfe"), ("data.bin", b"MZ")):
            pin, data = fixture(extra={path: (body, 0o644)})
            self.error("NATIVE_UNQUALIFIED", pure_payload, admit_bytes(pin, data, pin["asset"]))
        pin, data = fixture(extra={"node_modules/foo/index.js": (b"x", 0o644)})
        self.error("DEPENDENCY", pure_payload, admit_bytes(pin, data, pin["asset"]))

    def test_nested_package_constraints_are_scanned(self):
        pin, data = fixture(extra={"sub/package.json": (canonical({"cpu": ["x64"]}), 0o644)})
        self.error("DEPENDENCY", pure_payload, admit_bytes(pin, data, pin["asset"]))

    def test_duplicate_and_nonfinite_json_rejected(self):
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{', b'\xff'):
            self.error("JSON", strict_json, data)

    def test_absent_asset_and_no_renamed_substitution(self):
        pin = load_pin("theme-forge-stellar-loom")
        with tempfile.TemporaryDirectory() as directory:
            self.error("ASSET_ABSENT", intake, pin, Path(directory).resolve() / pin["asset"])


if __name__ == "__main__":
    unittest.main()
