"""Noarch input controls and exact retained unsigned header regressions."""
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import time
import unittest

from rs9.build_native import CommandReceipt, MockCommandRunner, SubprocessRunner
from rs9.build_rpm import (_authenticated_source_epoch, _noarch_build_inputs,
                           NOARCH_BUILDHOST, NOARCH_MACRO_QUERY, build_rpm_candidate)
from rs9.errors import ContractError
from rs9.release_core import digest
from rs9.rpm_header import header_delta, inspect_rpm, parse_header, tag_digest_map
from tests.rpm_fixtures import inventory_response
from tests.test_build_native import create_cli_fixture
import tests.test_build_rpm as rpm_tests


REFERENCE = Path(__file__).parent / "fixtures/rpm-noarch-run11-header-delta.json"


class NoarchReproducibilityTests(unittest.TestCase):
    def test_timestamp_has_one_validated_utc_day_authority(self):
        for timestamp in ("2026-09-29T00:00:00Z", "2026-09-29T23:59:59.999Z"):
            self.assertEqual(_authenticated_source_epoch(timestamp), (1790640000, timestamp))
        for timestamp in (None, "", "now", "2026-09-29", "2026-09-29T00:00:00+00:00",
                          "2026-02-30T00:00:00Z", "1970-01-01T12:00:00Z", "9999-01-01T00:00:00Z"):
            with self.subTest(timestamp=timestamp), self.assertRaises(ContractError):
                _authenticated_source_epoch(timestamp)

    def test_source_and_spec_inputs_modes_mtimes_and_macro_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            top = Path(tmp)
            for directory in ("SOURCES", "SPECS"):
                (top / directory).mkdir()
                (top / directory / "input").write_bytes(b"unchanged authenticated source bytes")
            calls = []
            def query(argv, cwd=None, env=None):
                calls.append((argv, cwd, env))
                return inventory_response(argv, cwd)
            runner = MockCommandRunner(available_tools={"rpm": "/fixture/bin/rpm"}, handlers={"rpm": query})
            argv, environment, witness = _noarch_build_inputs("2026-09-29T12:34:56Z", top, runner)
            self.assertEqual(argv[:2], ["--target", "noarch"])
            self.assertIn("optflags %{nil}", argv)
            self.assertIn("_buildtime 1790640000", argv)
            self.assertIn("_buildhost " + NOARCH_BUILDHOST, argv)
            self.assertIn("_target_platform noarch-redhat-linux", argv)
            self.assertEqual(environment["SOURCE_DATE_EPOCH"], "1790640000")
            self.assertEqual(calls[0], (["rpm", *argv, "--eval", NOARCH_MACRO_QUERY], top, environment))
            self.assertEqual(witness["source_date_epoch"], 1790640000)
            self.assertFalse(witness["physical_buildhost_claimed"])
            for path in top.glob("*/*"):
                self.assertEqual(path.stat().st_mtime, 1790640000)
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)
                self.assertEqual(path.read_bytes(), b"unchanged authenticated source bytes")
            causal = CommandReceipt(["rpm"], 0, b"wrong macro readback\n", b"", executed=True)
            runner.handlers["rpm"] = lambda *a, **kw: causal
            with self.assertRaises(ContractError) as caught:
                _noarch_build_inputs("2026-09-29T00:00:00Z", top, runner)
            self.assertIs(caught.exception.receipt, causal)
            self.assertEqual(caught.exception.details["substage"], "noarch-macro-readback")

    def test_complete_builder_binds_both_outputs_and_noarch_controls(self):
        harness = rpm_tests.BuildRpmTests()
        harness.setUp()
        self.addCleanup(harness.doCleanups)
        capture, intent, npm = create_cli_fixture(harness.root / "capture")
        runner = harness._setup_runner()
        result = build_rpm_candidate(capture, intent, "noarch", harness.scratch,
                                     offline_npm_archives=npm, runner=runner)
        build = next(row for row in runner.calls if row["argv"][0] == "rpmbuild")
        self.assertIn("-ba", build["argv"])
        self.assertIn("--target", build["argv"])
        witness = result["construction_witness"]["reproducibility"]
        self.assertEqual(build["env"]["SOURCE_DATE_EPOCH"], str(witness["source_date_epoch"]))
        self.assertTrue(witness["source_rpm"]["name"].endswith(".src.rpm"))
        self.assertEqual(witness["source_rpm"]["sha256"], digest(next(harness.scratch.rglob("*.src.rpm")).read_bytes()))
        self.assertEqual(result["manifest"]["reproducibility"], witness)
        self.assertEqual(result["derivation_record"]["evidence"]["reproducibility"], witness)

    def test_retained_reference_deltas_and_wrapper_clamp_are_exact(self):
        reference = json.loads(REFERENCE.read_bytes())
        for product in reference["products"].values():
            maps = product["main_tag_digests"]
            before, after = maps["x86_64-linux"], maps["aarch64-linux"]
            delta = sorted(int(tag) for tag in set(before) | set(after) if before.get(tag) != after.get(tag))
            self.assertEqual(delta, [1006, 1007, 1094, 1122, 1146])
            epoch, _ = _authenticated_source_epoch(product["observed_changelog_day_utc"] + "T00:00:00Z")
            for wrappers in product["wrapper_filemtimes"].values():
                self.assertTrue(wrappers)
                self.assertEqual(set(wrappers.values()), {epoch})

    @unittest.skipUnless(os.environ.get("RS9_RUN11_REFERENCE_DIR"), "exact captured references supplied by attended evidence replay")
    def test_exact_captured_pairs_match_derived_fixture_without_modifying_bytes(self):
        root = Path(os.environ["RS9_RUN11_REFERENCE_DIR"])
        for product in json.loads(REFERENCE.read_bytes())["products"].values():
            data = []
            for system in ("x86_64-linux", "aarch64-linux"):
                path = root / system / product["filename"]
                self.assertFalse(path.is_symlink())
                self.assertLess(path.stat().st_size, 2 * 1024**2)
                raw = path.read_bytes()
                self.assertEqual(digest(raw), product["unsigned_rpm_sha256"][system])
                self.assertEqual({str(k): v for k, v in tag_digest_map(raw).items()}, product["main_tag_digests"][system])
                data.append(raw)
            self.assertNotEqual(data[0], data[1])
            self.assertEqual(header_delta(*data), product["header_delta"])
            payloads = [inspect_rpm(raw)[2] for raw in data]
            self.assertEqual(payloads[0], payloads[1])
            self.assertEqual(digest(payloads[0]), product["compressed_payload_sha256"])
            from rs9.hosted_deb import _rpm_custody_unique
            bundles = [{"manifest": {"family": "rpm", "system": system},
                        "packages": {product["filename"]: root / system / product["filename"]}}
                       for system in ("x86_64-linux", "aarch64-linux")]
            with self.assertRaises(ContractError) as caught:
                _rpm_custody_unique(bundles)
            self.assertEqual(caught.exception.code, "CUSTODY_CONFLICT")
            self.assertEqual(caught.exception.custody_conflict["header_delta"], [1006, 1007, 1094, 1122, 1146])
            self.assertEqual(caught.exception.custody_conflict["first_system"], "x86_64-linux")

    def test_bounded_reader_rejects_truncation_indexes_and_string_mutation(self):
        def header(value):
            store = value + b"\0"
            return b"\x8e\xad\xe8\x01" + b"\0" * 4 + struct.pack(">II", 1, len(store)) + struct.pack(">IIII", 1007, 6, 0, 1) + store
        left, right = header(b"a"), header(b"b")
        self.assertEqual(header_delta(left, right), [1007])
        self.assertEqual(header_delta(left, left), [])
        self.assertEqual(parse_header(left)[0][1007]["value"], ["a"])
        for bad in (b"", left[:-1], left[:8] + struct.pack(">II", 20001, 0), left[:-1] + b"x"):
            with self.assertRaises(ValueError):
                parse_header(bad)

    @unittest.skipUnless(shutil.which("rpmbuild") and shutil.which("rpm"), "native pinned RPM 6.0.2 tools unavailable")
    def test_native_pinned_repeated_source_and_binary_bytes_converge(self):
        runner = SubprocessRunner()
        if runner.run(["rpm", "--version"]).stdout_bytes.strip() != b"RPM version 6.0.2":
            self.skipTest("native RPM version differs from pinned 6.0.2")
        outputs = []
        with tempfile.TemporaryDirectory() as tmp:
            for index, flags in enumerate(("-march=x86-64 -mtune=generic", "-march=armv8-a")):
                top = Path(tmp) / ("different-builder-" + str(index))
                for directory in ("SOURCES", "SPECS", "BUILD", "BUILDROOT", "RPMS", "SRPMS"):
                    (top / directory).mkdir(parents=True)
                (top / "SOURCES/payload").write_bytes(b"released noarch payload\n")
                spec = top / "SPECS/repack.spec"
                spec.write_text("Name: rs9-repro-test\nVersion: 1\nRelease: 1.fc43\nSummary: Fixture only\nLicense: MIT\nBuildArch: noarch\nSource0: payload\n%description\nFixture only.\n%prep\n%build\n%install\nmkdir -p %{buildroot}/usr/share/rs9-repro-test\ncp -p %{SOURCE0} %{buildroot}/usr/share/rs9-repro-test/payload\n%files\n%attr(0644,root,root) /usr/share/rs9-repro-test/payload\n%changelog\n* Tue Sep 29 2026 RS9 Fixture <fixture@invalid> - 1-1\n- Fixture only\n")
                args, env, _ = _noarch_build_inputs("2026-09-29T12:00:00Z", top, runner)
                receipt = runner.run(["rpmbuild", "-ba", "--define", "_topdir " + str(top),
                    "--define", "optflags " + flags, "--define", "_buildhost ephemeral-" + str(index),
                    *args, str(spec)], env=env)
                self.assertEqual(receipt.exit_code, 0, "native fixture build failed; bounded receipt hashes: " + receipt.stderr_sha256)
                binary = next((top / "RPMS").rglob("*.rpm")).read_bytes()
                source = next((top / "SRPMS").glob("*.src.rpm")).read_bytes()
                outputs.append((binary, source))
                time.sleep(1.05)
            self.assertEqual(outputs[0], outputs[1], "native repeated RPM bytes differ")
            _, tags, _ = inspect_rpm(outputs[0][0])
            self.assertEqual(tags[1007]["value"], [NOARCH_BUILDHOST])
            self.assertEqual(tags[1006]["value"], [1790640000])
            self.assertEqual(tags[1122]["value"], [""])


if __name__ == "__main__":
    unittest.main()
