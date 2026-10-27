"""Tests for authenticated dependency closure and hostile archive admission."""

import copy
import gzip
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import unittest

from rs9.tf_pypi_archive import AdmissionError, fail, read_tar, sha256
from rs9.tf_pypi_closure import (
    DEPENDENCIES,
    DEPENDENCIES_BY_ASSET,
    DEPENDENCIES_BY_NAME,
    DependencyPin,
    admit_dependency,
    closure_payload,
    dependencies_for_pin,
    dependency_licenses,
    load_dependencies,
)
from rs9.tf_pypi_model import admit_bytes, load_pin
from tests.tf_pypi_fixtures import ROOT, live_inputs


def write_tar(files: dict[str, tuple[bytes, int]], root: str = "package") -> bytes:
    """Create reproducible gzip PAX tar archive in memory."""
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, (body, mode) in sorted(files.items()):
                entry = tarfile.TarInfo(f"{root}/{name}")
                entry.size, entry.mode, entry.mtime = len(body), mode, 0
                archive.addfile(entry, io.BytesIO(body))
    return output.getvalue()


def make_dep_fixture(
    name="@xmldom/xmldom",
    version="0.9.12",
    license="MIT",
    asset="xmldom-0.9.12.tgz",
    *,
    pkg_overrides=None,
    extra_files=None,
    remove_license=False,
):
    """Create in-memory synthetic dependency archive and matching pin."""
    pkg = {
        "name": name,
        "version": version,
        "license": license,
        "description": "Synthetic dependency fixture",
    }
    if pkg_overrides:
        pkg.update(pkg_overrides)
    files = {
        "package.json": (json.dumps(pkg).encode(), 0o644),
        "index.js": (b"module.exports = {};\n", 0o644),
    }
    if not remove_license:
        files["LICENSE"] = (b"Synthetic MIT License.\n", 0o644)
    if extra_files:
        files.update(extra_files)
    data = write_tar(files, "package")
    pin = DependencyPin(
        name=name,
        version=version,
        asset=asset,
        size=len(data),
        sha256=sha256(data),
        license=license,
    )
    return pin, data


def make_raw_tar_gz(entries, fmt=tarfile.PAX_FORMAT) -> bytes:
    """Helper to synthesize low-level tar.gz byte streams for hostile testing."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        with tarfile.open(fileobj=gz, mode="w", format=fmt) as tf:
            for e in entries:
                ti = tarfile.TarInfo(e.get("name", "package/file.txt"))
                ti.mode = e.get("mode", 0o644)
                ti.type = e.get("type", tarfile.REGTYPE)
                if "linkname" in e:
                    ti.linkname = e["linkname"]
                if "pax_headers" in e:
                    ti.pax_headers = e["pax_headers"]
                data = e.get("data", b"")
                ti.size = e.get("size", len(data) if ti.type == tarfile.REGTYPE else 0)
                if ti.type == tarfile.REGTYPE:
                    tf.addfile(ti, io.BytesIO(data))
                else:
                    tf.addfile(ti)
    return buf.getvalue()


def make_product_fixture(project="theme-forge-stellar-loom", *, changes=None, extra=None):
    """Create synthetic product pin and admitted tar bytes without importing backend."""
    pin = copy.deepcopy(load_pin(project))
    package = {
        "name": pin["npm_name"],
        "version": pin["version"],
        "license": pin["license"],
        "engines": {"node": ">=22"},
        "bin": pin["bins"],
    }
    package.update(changes or {})
    files = {
        "package.json": (json.dumps(package).encode(), 0o644),
        "LICENSE": (b"Synthetic license fixture, not upstream legal bytes.\n", 0o644),
        "NOTICE": (b"Synthetic fixture only.\n", 0o644),
        "COMMERCIAL-LICENSE.md": (b"Synthetic commercial notice.\n", 0o644),
    }
    for command, target in pin["bins"].items():
        body = f"process.stdout.write({json.dumps(pin['version'] + chr(10))});\n".encode()
        files[target] = (body, 0o755)
    files.update(extra or {})
    data = write_tar(files, "package")
    pin.update(size=len(data), sha256=sha256(data))
    return pin, data


class TfPypiClosureTests(unittest.TestCase):
    def assert_error(self, code: str, func, *args, **kwargs):
        with self.assertRaises(AdmissionError) as caught:
            func(*args, **kwargs)
        expected = "TF_PYPI_" + code if not code.startswith("TF_PYPI_") else code
        self.assertEqual(caught.exception.code, expected)

    def test_dependencies_constant_pins(self):
        self.assertEqual(len(DEPENDENCIES), 3)

        expected_records = {
            "@xmldom/xmldom": {
                "version": "0.9.12",
                "asset": "xmldom-0.9.12.tgz",
                "size": 109708,
                "sha256": "08245e18c248b957b4c6e07f8549ad5f55ae11b7a8abd4c1113a0fd61ddc67ee",
                "license": "MIT",
            },
            "fflate": {
                "version": "0.8.3",
                "asset": "fflate-0.8.3.tgz",
                "size": 173034,
                "sha256": "38c2cd824402407b43153c782274aec2ea83ea688e4aa0b743c5f2c305857d92",
                "license": "MIT",
            },
            "smol-toml": {
                "version": "1.8.0",
                "asset": "smol-toml-1.8.0.tgz",
                "size": 23162,
                "sha256": "1fc995be91cdb777fc13e20c2edfebaaf60ef4e4d2d5331caef2837b04d37892",
                "license": "BSD-3-Clause",
            },
        }

        for pin in DEPENDENCIES:
            self.assertIn(pin.name, expected_records)
            exp = expected_records[pin.name]
            self.assertEqual(pin.version, exp["version"])
            self.assertEqual(pin.asset, exp["asset"])
            self.assertEqual(pin.size, exp["size"])
            self.assertEqual(pin.sha256, exp["sha256"])
            self.assertEqual(pin.license, exp["license"])

            # Verify dict access
            self.assertEqual(pin["name"], pin.name)
            self.assertEqual(pin["version"], exp["version"])
            self.assertEqual(pin["asset"], exp["asset"])
            self.assertEqual(pin["size"], exp["size"])
            self.assertEqual(pin["sha256"], exp["sha256"])
            self.assertEqual(pin["license"], exp["license"])

            # Verify integer index access
            self.assertEqual(pin[0], pin.name)
            self.assertEqual(pin[1], exp["version"])
            self.assertEqual(pin[2], exp["asset"])
            self.assertEqual(pin[3], exp["size"])
            self.assertEqual(pin[4], exp["sha256"])
            self.assertEqual(pin[5], exp["license"])

        self.assertEqual(
            set(DEPENDENCIES_BY_ASSET.keys()),
            {"xmldom-0.9.12.tgz", "fflate-0.8.3.tgz", "smol-toml-1.8.0.tgz"},
        )
        self.assertEqual(set(DEPENDENCIES_BY_NAME.keys()), {"@xmldom/xmldom", "fflate", "smol-toml"})

    def test_dependency_authority_is_selected_per_burst_release(self):
        successor = load_pin(
            "theme-forge-stellar-burst",
            ROOT / "operators/tf-pypi/theme-forge-stellar-burst-0.7.0.json",
        )
        legacy = load_pin("theme-forge-stellar-burst")

        self.assertEqual([pin.version for pin in dependencies_for_pin(successor)],
                         ["0.9.12", "0.8.3", "1.9.1"])
        self.assertEqual([pin.version for pin in dependencies_for_pin(legacy)],
                         ["0.9.12", "0.8.3", "1.8.0"])
        self.assertEqual(DEPENDENCIES[-1].version, "1.8.0")
        self.assertEqual(dependencies_for_pin(legacy), DEPENDENCIES)

    def test_admit_real_dependencies(self):
        inputs = live_inputs(self)

        for pin in DEPENDENCIES:
            asset_path = inputs / pin.asset
            self.assertTrue(asset_path.is_file(), f"Asset {pin.asset} must exist")
            data = asset_path.read_bytes()
            files = admit_dependency(pin, data)
            self.assertIn("package/package.json", files)
            self.assertIn("package/LICENSE", files)
            self.assertTrue(all(p.startswith("package/") for p in files))
            self.assertTrue(all(mode in (0o644, 0o755) for _, mode in files.values()))

    def test_admit_synthetic_dependency(self):
        pin, data = make_dep_fixture()
        files = admit_dependency(pin, data)
        self.assertIn("package/package.json", files)
        self.assertIn("package/LICENSE", files)
        self.assertEqual(len(files), 3)

    def test_admit_dependency_pin_formats(self):
        pin, data = make_dep_fixture()
        # As dict
        self.assertIn("package/package.json", admit_dependency(dict(pin), data))
        # As tuple
        pin_tuple = (pin.name, pin.version, pin.asset, pin.size, pin.sha256, pin.license)
        self.assertIn("package/package.json", admit_dependency(pin_tuple, data))

    def test_admit_dependency_size_and_hash_negatives(self):
        pin, data = make_dep_fixture()
        self.assert_error("SIZE", admit_dependency, pin, data + b"\x00")
        self.assert_error("SIZE", admit_dependency, pin, data[:-1])
        flipped = bytearray(data)
        flipped[-1] ^= 0xFF
        self.assert_error("HASH", admit_dependency, pin, bytes(flipped))

    def test_admit_dependency_pin_schema_negatives(self):
        _, data = make_dep_fixture()
        bad_pins = [
            "not a pin",
            123,
            {"name": "x"},  # missing fields
            {"name": "x", "version": "1.0", "asset": "x.tgz", "size": "not-int", "sha256": "a" * 64, "license": "MIT"},
            {"name": "x", "version": "1.0", "asset": "x.zip", "size": 100, "sha256": "a" * 64, "license": "MIT"},
            {"name": "x", "version": "1.0", "asset": "x.tgz", "size": -5, "sha256": "a" * 64, "license": "MIT"},
            {"name": "x", "version": "1.0", "asset": "x.tgz", "size": 100, "sha256": "short", "license": "MIT"},
            (1, 2, 3),  # wrong length tuple
        ]
        for bad in bad_pins:
            with self.subTest(bad=bad):
                self.assert_error("PIN", admit_dependency, bad, data)

    def test_admit_dependency_identity_mismatches(self):
        for change, code in [
            ({"name": "@evil/xmldom"}, "NAME"),
            ({"version": "9.9.9"}, "VERSION"),
            ({"license": "GPL-3.0-only"}, "LICENSE"),
        ]:
            with self.subTest(code=code, change=change):
                pin, data = make_dep_fixture(pkg_overrides=change)
                expected_pin = DependencyPin(
                    name="@xmldom/xmldom",
                    version="0.9.12",
                    asset="xmldom-0.9.12.tgz",
                    size=len(data),
                    sha256=sha256(data),
                    license="MIT",
                )
                self.assert_error(code, admit_dependency, expected_pin, data)

    def test_admit_dependency_license_file_missing_or_empty(self):
        # Missing license file
        pin1, data1 = make_dep_fixture(remove_license=True)
        self.assert_error("LICENSE", admit_dependency, pin1, data1)

        # Empty license file
        pin2, data2 = make_dep_fixture(extra_files={"LICENSE": (b"", 0o644)})
        self.assert_error("LICENSE", admit_dependency, pin2, data2)

    def test_admit_dependency_confusion_and_nested_runtime_deps(self):
        for dep_key in (
            "dependencies",
            "optionalDependencies",
            "peerDependencies",
            "bundledDependencies",
            "bundleDependencies",
        ):
            with self.subTest(dep_key=dep_key):
                pin, data = make_dep_fixture(pkg_overrides={dep_key: {"evil-pkg": "1.0.0"}})
                self.assert_error("DEPENDENCY", admit_dependency, pin, data)

        # Pre-bundled node_modules in archive
        pin, data = make_dep_fixture(
            extra_files={"node_modules/subdep/index.js": (b"console.log('injected');\n", 0o644)}
        )
        self.assert_error("DEPENDENCY", admit_dependency, pin, data)

        # Subdirectory package.json with nested dependencies
        nested_pkg = json.dumps({"dependencies": {"another": "1.0.0"}}).encode()
        pin, data = make_dep_fixture(extra_files={"sub/package.json": (nested_pkg, 0o644)})
        self.assert_error("DEPENDENCY", admit_dependency, pin, data)

    def test_admit_dependency_install_lifecycle_scripts_negatives(self):
        lifecycle_scripts = [
            "preinstall",
            "install",
            "postinstall",
            "preprepare",
            "prepare",
            "postprepare",
        ]
        for script_name in lifecycle_scripts:
            with self.subTest(script=script_name):
                pin, data = make_dep_fixture(pkg_overrides={"scripts": {script_name: "echo pwned"}})
                self.assert_error("INSTALL_SCRIPT", admit_dependency, pin, data)

        # binding.gyp triggers native compile lifecycle on npm install
        pin, data = make_dep_fixture(extra_files={"binding.gyp": (b"{}", 0o644)})
        self.assert_error("INSTALL_SCRIPT", admit_dependency, pin, data)

        # Subdirectory package.json with install lifecycle script
        nested_pkg = json.dumps({"scripts": {"postinstall": "sh evil.sh"}}).encode()
        pin, data = make_dep_fixture(extra_files={"sub/package.json": (nested_pkg, 0o644)})
        self.assert_error("INSTALL_SCRIPT", admit_dependency, pin, data)

    def test_admit_dependency_native_binary_negatives(self):
        for ext, body in [
            ("lib/addon.node", b"binary"),
            ("lib/helper.so", b"binary"),
            ("lib/helper.dylib", b"binary"),
            ("lib/helper.dll", b"binary"),
            ("lib/helper.exe", b"binary"),
            ("lib/helper.a", b"binary"),
            ("lib/data.bin", b"\x7fELFfake"),
            ("lib/data.bin", b"MZfake"),
            ("lib/data.bin", b"\xcf\xfa\xed\xfe"),  # Mach-O
        ]:
            with self.subTest(ext=ext):
                pin, data = make_dep_fixture(extra_files={ext: (body, 0o644)})
                self.assert_error("NATIVE_UNQUALIFIED", admit_dependency, pin, data)

    def test_admit_dependency_hostile_archive_negatives(self):
        base_pkg = json.dumps({"name": "test-pkg", "version": "1.0.0", "license": "MIT"}).encode()
        lic = b"MIT License\n"

        # Corrupt / non-gzip data
        pin = DependencyPin("test-pkg", "1.0.0", "test-pkg-1.0.0.tgz", 16, sha256(b"not-gzip-archive"), "MIT")
        self.assert_error("ARCHIVE", admit_dependency, pin, b"not-gzip-archive")

        # Symlink in tar
        data_symlink = make_raw_tar_gz([
            {"name": "package/package.json", "data": base_pkg},
            {"name": "package/LICENSE", "data": lic},
            {"name": "package/link.js", "type": tarfile.SYMTYPE, "linkname": "/etc/passwd"},
        ])
        pin_symlink = DependencyPin("test-pkg", "1.0.0", "test-pkg-1.0.0.tgz", len(data_symlink), sha256(data_symlink), "MIT")
        self.assert_error("LINK", admit_dependency, pin_symlink, data_symlink)

        # Path traversal
        data_traversal = make_raw_tar_gz([
            {"name": "package/package.json", "data": base_pkg},
            {"name": "package/LICENSE", "data": lic},
            {"name": "package/../../evil.js", "data": b"evil"},
        ])
        pin_traversal = DependencyPin("test-pkg", "1.0.0", "test-pkg-1.0.0.tgz", len(data_traversal), sha256(data_traversal), "MIT")
        self.assert_error("PATH", admit_dependency, pin_traversal, data_traversal)

        # Invalid mode
        data_mode = make_raw_tar_gz([
            {"name": "package/package.json", "data": base_pkg, "mode": 0o777},
            {"name": "package/LICENSE", "data": lic},
        ])
        pin_mode = DependencyPin("test-pkg", "1.0.0", "test-pkg-1.0.0.tgz", len(data_mode), sha256(data_mode), "MIT")
        self.assert_error("MODE", admit_dependency, pin_mode, data_mode)

        # Duplicate case collision
        data_case = make_raw_tar_gz([
            {"name": "package/package.json", "data": base_pkg},
            {"name": "package/LICENSE", "data": lic},
            {"name": "package/File.js", "data": b"1"},
            {"name": "package/file.js", "data": b"2"},
        ])
        pin_case = DependencyPin("test-pkg", "1.0.0", "test-pkg-1.0.0.tgz", len(data_case), sha256(data_case), "MIT")
        self.assert_error("DUPLICATE", admit_dependency, pin_case, data_case)

        # Malformed JSON in package.json
        data_json = make_raw_tar_gz([
            {"name": "package/package.json", "data": b'{"name": "test-pkg", "name": "dup"}'},
            {"name": "package/LICENSE", "data": lic},
        ])
        pin_json = DependencyPin("test-pkg", "1.0.0", "test-pkg-1.0.0.tgz", len(data_json), sha256(data_json), "MIT")
        self.assert_error("JSON", admit_dependency, pin_json, data_json)

    def test_closure_payload_burst_success(self):
        inputs = live_inputs(self)

        burst_pin = load_pin("theme-forge-stellar-burst")
        burst_data = (inputs / burst_pin["asset"]).read_bytes()
        burst_files = admit_bytes(burst_pin, burst_data, burst_pin["asset"])

        deps = {p.asset: (inputs / p.asset).read_bytes() for p in DEPENDENCIES}
        closed1 = closure_payload(burst_pin, burst_files, deps)
        closed2 = closure_payload(burst_pin, burst_files, deps)

        # Deterministic
        self.assertEqual(closed1, closed2)
        self.assertEqual(list(closed1.keys()), sorted(closed1.keys()))

        # Total file count check: 356 upstream + 15 xmldom + 17 fflate + 19 smol-toml = 407
        self.assertEqual(len(closed1), 407)

        # Upstream files preserved exactly
        for path, (data, mode) in burst_files.items():
            self.assertIn(path, closed1)
            self.assertEqual(closed1[path], (data, mode))

        # Node modules correctly positioned
        nm_files = {p: v for p, v in closed1.items() if "node_modules" in p}
        self.assertEqual(len(nm_files), 51)
        self.assertTrue(all(p.startswith("package/node_modules/") for p in nm_files))

        # Check expected paths for each dependency
        self.assertIn("package/node_modules/@xmldom/xmldom/package.json", closed1)
        self.assertIn("package/node_modules/@xmldom/xmldom/LICENSE", closed1)
        self.assertIn("package/node_modules/fflate/package.json", closed1)
        self.assertIn("package/node_modules/fflate/LICENSE", closed1)
        self.assertIn("package/node_modules/smol-toml/package.json", closed1)
        self.assertIn("package/node_modules/smol-toml/LICENSE", closed1)

    def test_closure_payload_burst_dependency_negatives(self):
        inputs = live_inputs(self)

        burst_pin = load_pin("theme-forge-stellar-burst")
        burst_data = (inputs / burst_pin["asset"]).read_bytes()
        burst_files = admit_bytes(burst_pin, burst_data, burst_pin["asset"])
        valid_deps = {p.asset: (inputs / p.asset).read_bytes() for p in DEPENDENCIES}

        # Missing dependency
        missing_deps = dict(valid_deps)
        del missing_deps["xmldom-0.9.12.tgz"]
        self.assert_error("DEPENDENCY", closure_payload, burst_pin, burst_files, missing_deps)

        # Extra dependency
        extra_deps = dict(valid_deps)
        extra_deps["unexpected-dep-1.0.0.tgz"] = b"extra"
        self.assert_error("DEPENDENCY", closure_payload, burst_pin, burst_files, extra_deps)

        # Non-mapping dependencies argument
        self.assert_error("DEPENDENCY", closure_payload, burst_pin, burst_files, None)
        self.assert_error("DEPENDENCY", closure_payload, burst_pin, burst_files, ["not", "a", "map"])

        # Corrupt dependency bytes
        corrupted_deps = dict(valid_deps)
        corrupted_deps["xmldom-0.9.12.tgz"] = corrupted_deps["xmldom-0.9.12.tgz"][:-1] + bytes([corrupted_deps["xmldom-0.9.12.tgz"][-1] ^ 0xFF])
        self.assert_error("HASH", closure_payload, burst_pin, burst_files, corrupted_deps)

        # Upstream Burst package.json with wrong version requirement
        bad_pkg_files = copy.deepcopy(burst_files)
        pkg = json.loads(bad_pkg_files["package/package.json"][0])
        pkg["dependencies"]["fflate"] = "^0.8.3"  # non-exact
        bad_pkg_files["package/package.json"] = (json.dumps(pkg).encode(), 0o644)
        self.assert_error("DEPENDENCY", closure_payload, burst_pin, bad_pkg_files, valid_deps)

        # Upstream Burst package.json with extra dependency
        bad_pkg_files2 = copy.deepcopy(burst_files)
        pkg2 = json.loads(bad_pkg_files2["package/package.json"][0])
        pkg2["dependencies"]["extra-lib"] = "1.0.0"
        bad_pkg_files2["package/package.json"] = (json.dumps(pkg2).encode(), 0o644)
        self.assert_error("DEPENDENCY", closure_payload, burst_pin, bad_pkg_files2, valid_deps)

        # Upstream Burst package.json with missing dependency
        bad_pkg_files3 = copy.deepcopy(burst_files)
        pkg3 = json.loads(bad_pkg_files3["package/package.json"][0])
        del pkg3["dependencies"]["smol-toml"]
        bad_pkg_files3["package/package.json"] = (json.dumps(pkg3).encode(), 0o644)
        self.assert_error("DEPENDENCY", closure_payload, burst_pin, bad_pkg_files3, valid_deps)

        # Upstream Burst files already containing node_modules
        bad_files_nm = copy.deepcopy(burst_files)
        bad_files_nm["package/node_modules/preinstalled/index.js"] = (b"pre", 0o644)
        self.assert_error("DEPENDENCY", closure_payload, burst_pin, bad_files_nm, valid_deps)

    def test_closure_payload_loom_and_sail(self):
        inputs = live_inputs(self)

        valid_deps = {p.asset: (inputs / p.asset).read_bytes() for p in DEPENDENCIES}

        for project in ("theme-forge-stellar-loom", "theme-forge-solar-sail"):
            with self.subTest(project=project):
                pin = load_pin(project)
                data = (inputs / pin["asset"]).read_bytes()
                files = admit_bytes(pin, data, pin["asset"])

                # Normal call with empty / None closure -> succeeds, returns original files
                self.assertEqual(closure_payload(pin, files, {}), files)
                self.assertEqual(closure_payload(pin, files, None), files)

                # Passing closure dependencies to Loom / Sail is strictly rejected
                self.assert_error("DEPENDENCY", closure_payload, pin, files, valid_deps)

                # Upstream package having runtime dependencies is strictly rejected
                bad_files = copy.deepcopy(files)
                pkg = json.loads(bad_files["package/package.json"][0])
                pkg["dependencies"] = {"any-dep": "1.0.0"}
                bad_files["package/package.json"] = (json.dumps(pkg).encode(), 0o644)
                self.assert_error("DEPENDENCY", closure_payload, pin, bad_files, {})

    def test_closure_payload_unsupported_product(self):
        pin, data = make_product_fixture("theme-forge-stellar-loom")
        files = admit_bytes(pin, data, pin["asset"])
        fake_pin = dict(pin, project="theme-forge-nebular-fusion")
        self.assert_error("PRODUCT", closure_payload, fake_pin, files, {})

    def test_dependency_licenses(self):
        inputs = live_inputs(self)

        deps = {p.asset: (inputs / p.asset).read_bytes() for p in DEPENDENCIES}
        lics = dependency_licenses(deps)

        expected_keys = {
            "node_modules/@xmldom/xmldom/LICENSE",
            "node_modules/fflate/LICENSE",
            "node_modules/smol-toml/LICENSE",
        }
        self.assertEqual(set(lics.keys()), expected_keys)
        for key in expected_keys:
            body, mode = lics[key]
            self.assertGreater(len(body), 0)
            self.assertEqual(mode, 0o644)

        # Empty dependencies returns empty dict
        self.assertEqual(dependency_licenses({}), {})

        # Non-mapping input fails closed
        self.assert_error("DEPENDENCY", dependency_licenses, "bad-input")

        # Unknown asset fails closed
        self.assert_error("DEPENDENCY", dependency_licenses, {"unknown.tgz": b"..."})

        # Extraction from already closed files payload dict
        burst_pin = load_pin("theme-forge-stellar-burst")
        burst_data = (inputs / burst_pin["asset"]).read_bytes()
        burst_files = admit_bytes(burst_pin, burst_data, burst_pin["asset"])
        closed = closure_payload(burst_pin, burst_files, deps)

        lics_from_closed = dependency_licenses(closed)
        self.assertEqual(lics_from_closed, lics)

    def test_load_dependencies(self):
        inputs = live_inputs(self)

        loaded = load_dependencies(inputs)
        self.assertEqual(set(loaded.keys()), {p.asset for p in DEPENDENCIES})
        for pin in DEPENDENCIES:
            self.assertEqual(len(loaded[pin.asset]), pin.size)
            self.assertEqual(sha256(loaded[pin.asset]), pin.sha256)

        # Absent directory raises ASSET_ABSENT
        self.assert_error("ASSET_ABSENT", load_dependencies, "/nonexistent/path/for/tests")

        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir).resolve()
            # Empty dir: missing all assets
            self.assert_error("ASSET_ABSENT", load_dependencies, tmppath)

            for p in DEPENDENCIES:
                (tmppath / p.asset).write_bytes((inputs / p.asset).read_bytes())
            # Truncate one asset
            (tmppath / DEPENDENCIES[0].asset).write_bytes(b"short")
            self.assert_error("SIZE", load_dependencies, tmppath)

            # Mutate hash of one asset with exact size
            real_data = (inputs / DEPENDENCIES[0].asset).read_bytes()
            corrupted = real_data[:-1] + bytes([real_data[-1] ^ 0xFF])
            (tmppath / DEPENDENCIES[0].asset).write_bytes(corrupted)
            self.assert_error("HASH", load_dependencies, tmppath)


if __name__ == "__main__":
    unittest.main()
