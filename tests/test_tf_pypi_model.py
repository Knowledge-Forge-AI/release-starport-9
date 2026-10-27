"""Exact first-wave identities and negative npm payload admission."""
import copy
import tempfile
from pathlib import Path
import unittest

from rs9.tf_pypi_archive import AdmissionError, canonical, fail, physical_bytes, read_tar, sha256
from rs9.tf_pypi_backend import write_tar
from rs9.tf_pypi_intake import asset_url
from rs9.tf_pypi_model import (DISTRIBUTIONS, PRODUCTS, TARGETS, admit_bytes, build_pin,
                              intake, load_pin, pure_payload, strict_json, validate_pin)
from tests.tf_pypi_fixtures import ROOT, fixture


class ModelTests(unittest.TestCase):
    def error(self, code, function, *args):
        with self.assertRaises(AdmissionError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, "TF_PYPI_" + code)

    def test_frozen_pins_three_only_blocked(self):
        expected_versions = {
            "theme-forge-stellar-burst": ("0.6.1", "0.6.1.post1"),
            "theme-forge-stellar-loom": ("0.4.0", "0.4.0.post1"),
            "theme-forge-solar-sail": ("0.2.1", "0.2.1.post1"),
        }
        for product, (upstream, dist_ver) in expected_versions.items():
            pin = load_pin(product)
            self.assertEqual(pin["schema"], "rs9.tf-pypi-intake.v2")
            self.assertEqual(pin["version"], upstream)
            self.assertEqual(pin["distribution_version"], dist_ver)
            self.assertEqual(DISTRIBUTIONS[product], dist_ver)
            self.assertEqual(pin["candidate_platforms"], list(TARGETS))
            self.assertEqual(pin["qualified_platforms"], list(TARGETS))
            self.assertIn(pin["source_status"], {"READY", "BLOCKED"})
            self.assertEqual(bool(pin["withheld"]), pin["source_status"] == "BLOCKED")
            self.assertEqual(validate_pin(pin), pin)
        self.error("PRODUCT", load_pin, "theme-forge-nebular-fusion")

    def test_successor_dependency_authority_rejects_mixed_stale_history(self):
        successor_path = ROOT / "operators/tf-pypi/theme-forge-stellar-burst-0.7.0.json"
        successor = load_pin("theme-forge-stellar-burst", successor_path)
        legacy = load_pin("theme-forge-stellar-burst")

        self.assertEqual(successor["source_status"], "READY")
        self.assertEqual(successor["qualified_platforms"], list(TARGETS))
        self.assertEqual(successor["source_commit"], "3edb9d2c40dd19a2b7d97d9309bc210e7fed711c")
        self.assertEqual(successor["dependencies"][-1]["version"], "1.9.1")
        self.assertEqual(legacy["version"], "0.6.1")
        self.assertEqual(legacy["source_commit"], "a3e89683f92b8240c800ed303c866e7b12aa3277")
        self.assertEqual(legacy["dependencies"][-1]["version"], "1.8.0")

        mixed = copy.deepcopy(successor)
        mixed["dependencies"][-1] = copy.deepcopy(legacy["dependencies"][-1])
        self.error("PIN", validate_pin, mixed)

        requalified = copy.deepcopy(successor)
        requalified["qualified_platforms"] = list(TARGETS)
        self.assertEqual(build_pin(requalified)["qualified_platforms"], [])

    def test_distribution_version_and_platform_pin_negatives(self):
        pin = load_pin("theme-forge-stellar-loom")
        for bad_dv in ("0.4.0", "0.4.0.post2", "0.6.1.post1", "0.2.1.post1", "1.0.0.post1", "", None):
            with self.subTest(distribution_version=bad_dv):
                self.error("PIN", validate_pin, {**pin, "distribution_version": bad_dv})
        missing_dv = dict(pin)
        missing_dv.pop("distribution_version")
        self.error("PIN", validate_pin, missing_dv)
        self.error("PIN", validate_pin, {**pin, "schema": "rs9.tf-pypi-intake.v1"})
        for bad_candidates in (
            ["darwin-arm64"],
            ["darwin-arm64", "linux-x64-gnu", "linux-arm64-gnu"],
            ["darwin-arm64", "linux-arm64-gnu", "linux-x64-gnu", "darwin-x64"],
        ):
            with self.subTest(candidate_platforms=bad_candidates):
                self.error("PIN", validate_pin, {**pin, "candidate_platforms": bad_candidates})
        for bad_qualified in (
            ["darwin-x64"],
            ["win32-x64"],
            ["darwin-arm64", "darwin-arm64"],
            "darwin-arm64",
        ):
            with self.subTest(qualified_platforms=bad_qualified):
                self.error("PIN", validate_pin, {**pin, "qualified_platforms": bad_qualified})
        self.assertEqual(
            validate_pin({**pin, "qualified_platforms": list(TARGETS)})["qualified_platforms"],
            list(TARGETS),
        )
        blocked = {
            **pin,
            "qualified_platforms": list(TARGETS),
            "source_status": "BLOCKED",
            "withheld": ["awaiting native matrix receipts"],
        }
        self.assertEqual(build_pin(blocked), {**blocked, "qualified_platforms": []})

    def test_upstream_package_json_and_asset_url_reject_post_suffix(self):
        for project in PRODUCTS:
            pin = load_pin(project)
            url = asset_url(pin)
            self.assertIn(f"/releases/download/v{pin['version']}/{pin['asset']}", url)
            self.assertNotIn("post", url)
            bad_pin, bad_data = fixture(project, changes={"version": pin["distribution_version"]})
            self.error("VERSION", admit_bytes, bad_pin, bad_data, bad_pin["asset"])

    def test_legacy_artifact_approvals_stay_immutable(self):
        expected = {
            "theme-forge-stellar-burst": (
                "0.6.1",
                "773583c0a629945ae25adffe78014828de90ab72b2da78f91a1c20b88be819bf",
            ),
            "theme-forge-stellar-loom": (
                "0.4.0",
                "452e65e9f0b4e937afc4b3e50bd3fa38cc93be5f4feecca531c85f9791e23bed",
            ),
            "theme-forge-solar-sail": (
                "0.2.1",
                "fcde62f45ee4f1fec92530b524c1eca2090790815c14cb1076fd227fb3fb8e77",
            ),
        }
        for project, (upstream_version, expected_sha) in expected.items():
            path = ROOT / "operators/tf-pypi" / f"{project}-artifacts.json"
            manifest = strict_json(physical_bytes(path))
            self.assertEqual(manifest["schema"], "rs9.tf-pypi-candidate-set.v1")
            self.assertEqual(manifest["project"], project)
            self.assertEqual(manifest["version"], upstream_version)
            self.assertEqual(len(manifest["files"]), 2)
            self.assertEqual(manifest["set_sha256"], expected_sha)

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
