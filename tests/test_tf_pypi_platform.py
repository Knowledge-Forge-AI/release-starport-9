"""Platform-constrained artifacts, runtime mismatch and unsupported sdist hosts."""
import base64
import hashlib
import json
from pathlib import Path
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch

from rs9.tf_pypi_archive import AdmissionError, sha256
from rs9.tf_pypi_backend import (
    HELPERS,
    build_pair,
    names,
    payload,
    sdist_entries,
    wheel_entries,
    write_tar,
    write_zip,
)
from rs9.tf_pypi_closure import DEPENDENCIES, DependencyPin
from rs9.tf_pypi_launcher import check_platform
from rs9.tf_pypi_model import TARGETS
from rs9.tf_pypi_platform import EXPECTED_TAGS, build_target, check_tag, host_key, pure_tag
from rs9.tf_pypi_verify import verify_pair
from tests.test_tf_pypi_native import (
    EXPECTED_PREBUILD_RELPATHS,
    make_synthetic_elf,
    make_synthetic_files,
    make_synthetic_macho,
)
from tests.tf_pypi_fixtures import fixture


def _synthetic_burst_fixture(*, native_overrides=None):
    native_entries = {
        path[len("package/"):]: value
        for path, value in make_synthetic_files().items()
        if path != "package/package.json"
    }
    if native_overrides:
        native_entries.update(native_overrides)
    dep_specs = {dep["name"]: dep["version"] for dep in DEPENDENCIES}
    pin, data = fixture(
        "theme-forge-stellar-burst",
        changes={"dependencies": dep_specs},
        extra=native_entries,
    )
    dep_blobs = {}
    synthetic_pins = []
    updated_pin_deps = []
    for dep in DEPENDENCIES:
        dep_pkg = {"name": dep["name"], "version": dep["version"], "license": dep["license"]}
        dep_tar = write_tar(
            {
                "package.json": (json.dumps(dep_pkg).encode("utf-8"), 0o644),
                "LICENSE": (f"Synthetic {dep['name']} {dep['license']} license.\n".encode("utf-8"), 0o644),
            },
            "package",
        )
        dep_blobs[dep["asset"]] = dep_tar
        digest = sha256(dep_tar)
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(dep_tar).digest()).decode("ascii")
        synthetic_pins.append(
            DependencyPin(
                name=dep["name"],
                version=dep["version"],
                asset=dep["asset"],
                size=len(dep_tar),
                sha256=digest,
                license=dep["license"],
            )
        )
        updated_pin_deps.append(
            {
                "name": dep["name"],
                "version": dep["version"],
                "asset": dep["asset"],
                "size": len(dep_tar),
                "sha256": digest,
                "license": dep["license"],
                "url": f"https://registry.npmjs.org/{dep['name']}/-/{dep['asset']}",
                "integrity": integrity,
            }
        )
    pin["dependencies"] = updated_pin_deps
    return pin, data, dep_blobs, synthetic_pins


class PlatformTests(unittest.TestCase):
    def test_unsupported_host_and_musl_refuse(self):
        for system, machine, libc in [("Windows", "AMD64", ""), ("Linux", "x86_64", "musl"),
                                      ("Linux", "ppc64", "glibc")]:
            with self.subTest(system=system), patch("platform.system", return_value=system), \
                    patch("platform.machine", return_value=machine), patch("platform.libc_ver", return_value=(libc, "1")):
                with self.assertRaises(AdmissionError):
                    host_key()

    def test_three_candidate_targets_build_with_unqualified_pin_and_reject_others(self):
        for project in ("theme-forge-stellar-loom", "theme-forge-solar-sail"):
            pin, data = fixture(project)
            self.assertEqual(pin["qualified_platforms"], [])
            package = names(pin)[0]
            for target in TARGETS:
                self.assertEqual(build_target(pin, target), target)
                entries = wheel_entries(pin, data, target=target)
                launcher = entries[f"{package}/launcher.py"][0]
                _, tag, _ = payload(pin, data, target=target)
                self.assertEqual(tag, EXPECTED_TAGS[project][target])
                self.assertEqual(pure_tag(target), tag)
                if target.startswith("linux"):
                    self.assertIn(b"MIN_GLIBC = (2, 28)", launcher)
                else:
                    self.assertNotIn(b"MIN_GLIBC =", launcher)
            for unsupported in ("win32-x64", "darwin-x64", "linux-musl"):
                with self.subTest(project=project, target=unsupported), self.assertRaises(AdmissionError) as caught:
                    build_target(pin, unsupported)
                self.assertEqual(caught.exception.code, "TF_PYPI_UNSUPPORTED_PLATFORM")
            with patch("rs9.tf_pypi_platform.host_key", return_value="darwin-x64"), self.assertRaises(AdmissionError) as caught:
                wheel_entries(pin, data)
            self.assertEqual(caught.exception.code, "TF_PYPI_UNSUPPORTED_PLATFORM")
            with patch("rs9.tf_pypi_platform.host_key", return_value="linux-x64-gnu"):
                self.assertTrue(wheel_entries(pin, data, target="darwin-arm64"))

    def test_burst_synthetic_addons_enforce_exact_13_and_2_33_floors(self):
        pin, data, deps, synthetic_pins = _synthetic_burst_fixture()
        by_asset = {d["asset"]: d for d in synthetic_pins}
        with self.assertRaises(AdmissionError) as caught:
            names(pin)
        self.assertEqual(caught.exception.code, "TF_PYPI_PIN")
        with patch("rs9.tf_pypi_closure.DEPENDENCIES", synthetic_pins), \
                patch("rs9.tf_pypi_closure.DEPENDENCIES_BY_ASSET", by_asset):
            package = names(pin)[0]
            for target, expected_tag in EXPECTED_TAGS["theme-forge-stellar-burst"].items():
                _, tag, _ = payload(pin, data, deps, target=target)
                self.assertEqual(tag, expected_tag)
                entries = wheel_entries(pin, data, deps, target=target)
                launcher = entries[f"{package}/launcher.py"][0]
                if target.startswith("linux"):
                    self.assertIn(b"MIN_GLIBC = (2, 33)", launcher)
                else:
                    self.assertNotIn(b"MIN_GLIBC =", launcher)

        mismatches = [
            (
                "darwin-arm64",
                {EXPECTED_PREBUILD_RELPATHS["darwin-arm64"]: (make_synthetic_macho(arch="arm64", min_os=(14, 0)), 0o755)},
            ),
            (
                "linux-arm64-gnu",
                {EXPECTED_PREBUILD_RELPATHS["linux-arm64-gnu"]: (make_synthetic_elf(arch="arm64", glibc_versions=("2.34",)), 0o755)},
            ),
            (
                "linux-arm64-gnu",
                {EXPECTED_PREBUILD_RELPATHS["linux-arm64-gnu"]: (make_synthetic_elf(arch="arm64", glibc_versions=("2.28",)), 0o755)},
            ),
            (
                "linux-x64-gnu",
                {EXPECTED_PREBUILD_RELPATHS["linux-x64-gnu"]: (make_synthetic_elf(arch="x86_64", glibc_versions=("2.34",)), 0o755)},
            ),
            (
                "linux-x64-gnu",
                {EXPECTED_PREBUILD_RELPATHS["linux-x64-gnu"]: (make_synthetic_elf(arch="x86_64", glibc_versions=("2.28",)), 0o755)},
            ),
        ]
        for target, override in mismatches:
            bad_pin, bad_data, bad_deps, bad_pins = _synthetic_burst_fixture(native_overrides=override)
            bad_by_asset = {d["asset"]: d for d in bad_pins}
            with self.subTest(target=target, override=list(override)), \
                    patch("rs9.tf_pypi_closure.DEPENDENCIES", bad_pins), \
                    patch("rs9.tf_pypi_closure.DEPENDENCIES_BY_ASSET", bad_by_asset), \
                    self.assertRaises(AdmissionError) as caught:
                payload(bad_pin, bad_data, bad_deps, target=target)
            self.assertEqual(caught.exception.code, "TF_PYPI_PLATFORM_TAG")

        with self.assertRaises(AdmissionError) as caught:
            check_tag(pin, "darwin-arm64", "macosx_11_0_arm64")
        self.assertEqual(caught.exception.code, "TF_PYPI_PLATFORM_TAG")

    def test_platform_wheel_cannot_be_relabelled_or_claim_purelib(self):
        pin, data = fixture()
        for mutation in ("filename", "tag", "purelib", "native"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                build_pair(pin, data, root, target="darwin-arm64")
                wheel = next(root.glob("*.whl"))
                files = wheel_entries(pin, data, target="darwin-arm64")
                info = names(pin)[2]
                if mutation == "filename":
                    wheel.rename(wheel.with_name(names(pin)[1] + "-py3-none-any.whl"))
                else:
                    if mutation == "native":
                        files[names(pin)[0] + "/payload/package/surplus.node"] = (b"\x7fELF", 0o644)
                    else:
                        header = files[info + "/WHEEL"][0]
                        files[info + "/WHEEL"] = (header.replace(b"false", b"true") if mutation == "purelib"
                                                 else header.replace(b"macosx_11_0_arm64", b"any"), 0o644)
                    wheel.write_bytes(write_zip(files))
                with self.assertRaises(AdmissionError):
                    verify_pair(pin, root, target="darwin-arm64")

    def test_node_platform_and_libc_preflight_boundaries(self):
        for facts in ({"platform": "darwin", "arch": "x64"}, {"platform": "linux", "arch": "arm64", "glibc": None}):
            result = CompletedProcess([], 0, json.dumps(facts), "")
            with patch("rs9.tf_pypi_launcher.PLATFORM_KEY", "darwin-arm64", create=True), \
                    patch("rs9.tf_pypi_launcher.subprocess.run", return_value=result), \
                    self.assertRaisesRegex(RuntimeError, "TF_PYPI_NODE_PLATFORM"):
                check_platform("/fixture/node")

        for floor, refused, accepted, key, arch in (
            ((2, 28), "2.27", "2.28", "linux-arm64-gnu", "arm64"),
            ((2, 33), "2.32", "2.33", "linux-x64-gnu", "x64"),
        ):
            bad_res = CompletedProcess([], 0, json.dumps({"platform": "linux", "arch": arch, "glibc": refused}), "")
            good_res = CompletedProcess([], 0, json.dumps({"platform": "linux", "arch": arch, "glibc": accepted}), "")
            with patch("rs9.tf_pypi_launcher.PLATFORM_KEY", key, create=True), \
                    patch("rs9.tf_pypi_launcher.MIN_GLIBC", floor, create=True), \
                    patch("rs9.tf_pypi_launcher.subprocess.run", return_value=bad_res), \
                    self.assertRaisesRegex(RuntimeError, "TF_PYPI_NODE_PLATFORM"):
                check_platform("/fixture/node")
            with patch("rs9.tf_pypi_launcher.PLATFORM_KEY", key, create=True), \
                    patch("rs9.tf_pypi_launcher.MIN_GLIBC", floor, create=True), \
                    patch("rs9.tf_pypi_launcher.subprocess.run", return_value=good_res):
                check_platform("/fixture/node")

    def test_sdist_contains_all_backend_modules_description_and_rs9_license(self):
        pin, data = fixture()
        entries = sdist_entries(pin, data, target="darwin-arm64")
        for helper in HELPERS:
            self.assertIn("_rs9_build/rs9/" + helper, entries)
        self.assertIn("_rs9_build/rs9/descriptions/stellar-loom.md", entries)
        self.assertEqual(entries["README.md"], entries["_rs9_build/rs9/descriptions/stellar-loom.md"])
        self.assertEqual(entries["RS9-LICENSE"], entries["_rs9_build/rs9/RS9-LICENSE"])


if __name__ == "__main__":
    unittest.main()
