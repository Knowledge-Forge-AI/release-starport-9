"""Noarch input controls and exact retained unsigned header regressions."""
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
import time
import unittest
from contextlib import ExitStack
from types import SimpleNamespace

from rs9.build_native import CommandReceipt, MockCommandRunner, SubprocessRunner
from rs9.build_rpm import (_authenticated_source_epoch, _noarch_build_inputs,
                           _render_rpm_spec, inspect_noarch_headers,
                           NOARCH_BUILDHOST, NOARCH_MACRO_QUERY, build_rpm_candidate)
from rs9.errors import ContractError
from rs9.records import sanitized
from rs9.release_core import digest
from rs9.rpm_header import header_delta, inspect_rpm, parse_header, tag_digest_map, RPM_HEADER_MAGIC
from tests.rpm_fixtures import inventory_response
from tests.test_build_native import create_cli_fixture
import tests.test_build_rpm as rpm_tests
from unittest import mock


REFERENCE = Path(__file__).parent / "fixtures/rpm-noarch-run11-header-delta.json"


def _make_synthetic_header(tags: dict[int, tuple[int, object]]) -> bytes:
    index_entries = []
    store = bytearray()
    for tag_id, (typ, val) in sorted(tags.items()):
        off = len(store)
        if typ in (3, 4):
            vals = val if isinstance(val, list) else [val]
            fmt = ">" + ("H" if typ == 3 else "I") * len(vals)
            chunk = struct.pack(fmt, *vals)
            store.extend(chunk)
            num = len(vals)
        elif typ == 6:
            s = val[0] if isinstance(val, list) else val
            chunk = s.encode("utf-8") + b"\0"
            store.extend(chunk)
            num = 1
        elif typ == 7:
            b = bytes.fromhex(val) if isinstance(val, str) else val
            store.extend(b)
            num = len(b)
        elif typ in (8, 9):
            vals = val if isinstance(val, list) else [val]
            for s in vals:
                store.extend(s.encode("utf-8") + b"\0")
            num = len(vals)
        else:
            raise ValueError(f"unsupported typ {typ}")
        index_entries.append(struct.pack(">IIII", tag_id, typ, off, num))

    return (
        RPM_HEADER_MAGIC
        + b"\0\0\0\0"
        + struct.pack(">II", len(index_entries), len(store))
        + b"".join(index_entries)
        + bytes(store)
    )


def _make_synthetic_rpm(main_tags: dict[int, tuple[int, object]], payload: bytes = b"payload") -> bytes:
    lead = b"\xed\xab\xee\xdb" + b"\0" * 92
    sig_header = _make_synthetic_header({1000: (6, "sig")})
    pad_len = ((len(sig_header) + 7) & ~7) - len(sig_header)
    padded_sig = sig_header + (b"\0" * pad_len)
    main_header = _make_synthetic_header(main_tags)
    return lead + padded_sig + main_header + payload


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
                spec.write_text("%global optflags %{nil}\nName: rs9-repro-test\nVersion: 1\nRelease: 1.fc43\nSummary: Fixture only\nLicense: MIT\nBuildArch: noarch\nSource0: payload\n%description\nFixture only.\n%prep\n%build\n%install\nmkdir -p %{buildroot}/usr/share/rs9-repro-test\ncp -p %{SOURCE0} %{buildroot}/usr/share/rs9-repro-test/payload\n%files\n%attr(0644,root,root) /usr/share/rs9-repro-test/payload\n%changelog\n* Tue Sep 29 2026 RS9 Fixture <fixture@invalid> - 1-1\n- Fixture only\n")
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

    def test_synthetic_spec_parse_reparse_boundary_applies_only_to_pure_js_noarch(self):
        """[synthetic] Spec-local optflags %{nil} applies only to pure-JS noarch (Loom & Sail) and comments are macro-clean."""
        # 1. Pure-JS noarch: Loom
        spec_loom = _render_rpm_spec(
            name="theme-forge-stellar-loom",
            version="0.4.0",
            revision=1,
            summary="Theme Forge Stellar Loom",
            lic="MIT",
            asset="loom.tar.gz",
            sha="sha-loom",
            arch="noarch",
            deps=[],
            cmds=[{"name": "loom", "path": "bin/loom"}],
            is_nebular=False,
            root="/tmp/loom",
            published_at="2026-09-29T12:00:00Z",
        ).decode("utf-8")
        self.assertIn("%global optflags %{nil}\n", spec_loom)
        for line in spec_loom.splitlines():
            if line.strip().startswith("#"):
                self.assertNotIn("%", line, f"Comment contains % macro: {line}")

        # 2. Pure-JS noarch: Sail
        spec_sail = _render_rpm_spec(
            name="theme-forge-solar-sail",
            version="0.2.1",
            revision=1,
            summary="Theme Forge Solar Sail",
            lic="MIT",
            asset="sail.tar.gz",
            sha="sha-sail",
            arch="noarch",
            deps=[],
            cmds=[{"name": "sail", "path": "bin/sail"}],
            is_nebular=False,
            root="/tmp/sail",
            published_at="2026-09-29T12:00:00Z",
        ).decode("utf-8")
        self.assertIn("%global optflags %{nil}\n", spec_sail)
        for line in spec_sail.splitlines():
            if line.strip().startswith("#"):
                self.assertNotIn("%", line, f"Comment contains % macro: {line}")

        # 3. Native Burst: x86_64 and aarch64
        for arch in ("x86_64", "aarch64"):
            spec_burst = _render_rpm_spec(
                name="theme-forge-stellar-burst",
                version="0.6.1",
                revision=1,
                summary="Theme Forge Stellar Burst",
                lic="MIT",
                asset="burst.tar.gz",
                sha="sha-burst",
                arch=arch,
                deps=[],
                cmds=[{"name": "burst", "path": "bin/burst"}],
                is_nebular=False,
                root="/tmp/burst",
                is_native_node=True,
                published_at="2026-09-29T12:00:00Z",
            ).decode("utf-8")
            self.assertNotIn("%global optflags %{nil}", spec_burst)
            self.assertIn(f"ExclusiveArch: {arch}", spec_burst)

        # 4. Native Nebular: x86_64 and aarch64
        for arch in ("x86_64", "aarch64"):
            spec_nebular = _render_rpm_spec(
                name="theme-forge-nebular-fusion",
                version="0.3.0",
                revision=1,
                summary="Theme Forge Nebular Fusion",
                lic="MIT",
                asset="nebular.tar.gz",
                sha="sha-nebular",
                arch=arch,
                deps=[],
                cmds=[{"name": "nebular", "path": "bin/nebular"}],
                is_nebular=True,
                root="/tmp/nebular",
                d_sha="dsha",
                i_sha="isha",
                published_at="2026-09-29T12:00:00Z",
            ).decode("utf-8")
            self.assertNotIn("%global optflags %{nil}", spec_nebular)
            self.assertIn(f"ExclusiveArch: {arch}", spec_nebular)

    def test_synthetic_noarch_build_inputs_relabels_eval_scope_and_spec_controls(self):
        """[synthetic] _noarch_build_inputs relabels macro eval scope and records spec_local_controls."""
        with tempfile.TemporaryDirectory() as tmp:
            top = Path(tmp)
            for directory in ("SOURCES", "SPECS"):
                (top / directory).mkdir()
                (top / directory / "input").write_bytes(b"content")
            runner = MockCommandRunner(
                available_tools={"rpm": "/fixture/bin/rpm"},
                handlers={"rpm": lambda argv, cwd=None, env=None: inventory_response(argv, cwd)},
            )
            argv, env, evidence = _noarch_build_inputs("2026-09-29T12:34:56Z", top, runner)
            self.assertEqual(evidence["macro_readback_scope"], "rpm-cli-context")
            self.assertEqual(evidence["spec_local_controls"], ["%global optflags %{nil}"])
            self.assertEqual(evidence["declared_buildhost"], NOARCH_BUILDHOST)
            self.assertFalse(evidence["physical_buildhost_claimed"])
            self.assertIn("optflags %{nil}", argv)

    def test_synthetic_native_baseline_golden_digests(self):
        """Synthetic render inputs; exact native spec bytes from the retained baseline."""
        expected = {
            ("theme-forge-stellar-burst", "x86_64"): "3fe64a07babb4e3ef319e9b6c8b62aff8207481b1354841cea7d3e9bf6e7e616",
            ("theme-forge-stellar-burst", "aarch64"): "3081a7426fa4a549dab879b8e66c2fe50e730a6e745f71de0573cb2edb2bdb19",
            ("theme-forge-nebular-fusion", "x86_64"): "2f918531df41d0622b1f8a6b6622ad7aacfb18193bbcbc81c6c0a9fecf84d4ec",
            ("theme-forge-nebular-fusion", "aarch64"): "006173c83284c129684cac9f80307786600f2bcdc5f31fc86c88d9f76c119727",
        }
        for (name, arch), sha in expected.items():
            spec = _render_rpm_spec(name=name, version="0.6.1", revision=1, summary="Fixture", lic="MIT",
                asset="release.tar.gz", sha="a"*64, arch=arch, deps=[], cmds=[{"name":"fixture","path":"bin/fixture"}],
                is_nebular=name.endswith("fusion"), root="/fixture/build", is_native_node=name.endswith("burst"),
                d_sha="b"*64, i_sha="c"*64, published_at="2026-09-29T12:00:00Z")
            self.assertEqual(digest(spec), sha)
            self.assertNotIn(b"%global optflags", spec)

    def test_synthetic_macro_stack_reset_and_spec_reparse_boundary(self):
        """Synthetic macro-stack model; header equality still requires hosted builds."""
        def finalize(spec_local, native_flags):
            stack = {"optflags": ""}  # command-line preflight
            stack["optflags"] = native_flags  # target configuration is reread
            for _ in range(2):  # BuildArch parses the spec again
                if spec_local: stack["optflags"] = ""
            return {1122: stack["optflags"], 1007: NOARCH_BUILDHOST}
        for spec_local in (False, True):
            left, right = (finalize(spec_local, flags) for flags in ("-m64", "-mbranch-protection=standard"))
            delta = [k for k in left if left[k] != right[k]]
            self.assertEqual(delta, [] if spec_local else [1122])
        self.assertEqual(finalize(False, "-m64")[1122], "-m64")

    def test_synthetic_inspect_noarch_headers_pass_fail_parse_failure_bytes_unchanged(self):
        """[synthetic] inspect_noarch_headers validates header constraints, handles parse failures, and preserves bytes."""
        epoch = 1790640000
        valid_bin_tags = {
            1006: (4, epoch),
            1007: (6, NOARCH_BUILDHOST),
            1022: (6, "noarch"),
            1094: (6, "reproducible-cookie"),
            1122: (6, ""),
            1132: (6, "sha256"),
            1146: (6, "source-pkg-id"),
        }
        valid_src_tags = {
            1006: (4, epoch),
            1007: (6, NOARCH_BUILDHOST),
            1122: (6, ""),
        }
        bin_rpm = _make_synthetic_rpm(valid_bin_tags, payload=b"bin-payload")
        src_rpm = _make_synthetic_rpm(valid_src_tags, payload=b"src-payload")
        bin_orig = bytes(bin_rpm)
        src_orig = bytes(src_rpm)

        # 1. Pass case
        res = inspect_noarch_headers(
            bin_rpm,
            src_rpm,
            epoch,
            expected_buildhost=NOARCH_BUILDHOST,
            spec_bytes=b"spec content",
            closure_sha="closure123",
        )
        self.assertEqual(res["status"], "pass")
        self.assertIsNone(res["reason"])
        self.assertEqual(res["failures"], [])
        self.assertEqual(res["binary_rpm"]["architecture"], "noarch")
        self.assertEqual(res["binary_rpm"]["buildtime"], epoch)
        self.assertEqual(res["binary_rpm"]["buildhost"], NOARCH_BUILDHOST)
        self.assertIsNone(res["binary_rpm"]["optflags"])
        self.assertEqual(res["binary_rpm"]["optflags_presence"], "empty")
        self.assertTrue(res["binary_rpm"]["optflags_absent_or_empty"])
        self.assertEqual(res["binary_rpm"]["compressed_payload_sha256"], digest(b"bin-payload"))
        self.assertEqual(res["source_rpm"]["compressed_payload_sha256"], digest(b"src-payload"))
        self.assertEqual(res["identities"]["closure_sha256"], "closure123")
        self.assertIn("1094", res["binary_rpm"]["tag_digests"])
        self.assertIn("1122", res["binary_rpm"]["tag_digests"])
        self.assertIn("1146", res["binary_rpm"]["tag_digests"])
        # Verify durable serialization sanitization passes
        sanitized(res)
        # Verify read-only: input bytes unchanged
        self.assertEqual(bin_rpm, bin_orig)
        self.assertEqual(src_rpm, src_orig)

        # 2. Failure: binary arch mismatch
        bad_arch_rpm = _make_synthetic_rpm({**valid_bin_tags, 1022: (6, "x86_64")})
        res_arch = inspect_noarch_headers(bad_arch_rpm, src_rpm, epoch)
        self.assertEqual(res_arch["status"], "fail")
        self.assertEqual(res_arch["reason"], "arch-mismatch")

        # 3. Failure: binary buildtime epoch mismatch
        bad_epoch_rpm = _make_synthetic_rpm({**valid_bin_tags, 1006: (4, 12345)})
        res_epoch = inspect_noarch_headers(bad_epoch_rpm, src_rpm, epoch)
        self.assertEqual(res_epoch["status"], "fail")
        self.assertEqual(res_epoch["reason"], "buildtime-epoch-mismatch")

        # 4. Failure: binary buildhost mismatch
        bad_host_rpm = _make_synthetic_rpm({**valid_bin_tags, 1007: (6, "wrong-host")})
        res_host = inspect_noarch_headers(bad_host_rpm, src_rpm, epoch)
        self.assertEqual(res_host["status"], "fail")
        self.assertEqual(res_host["reason"], "buildhost-mismatch")

        # 5. Failure: binary optflags populated
        bad_opt_rpm = _make_synthetic_rpm({**valid_bin_tags, 1122: (6, "-O2 -g")})
        res_opt = inspect_noarch_headers(bad_opt_rpm, src_rpm, epoch)
        self.assertEqual(res_opt["status"], "fail")
        self.assertEqual(res_opt["reason"], "optflags-non-empty")
        for typ, value in ((6, " "), (4, 0), (8, ["", ""])):
            unexpected = _make_synthetic_rpm({**valid_bin_tags, 1122: (typ, value)})
            self.assertEqual(inspect_noarch_headers(unexpected, src_rpm, epoch)["status"], "fail")
        absent_flags = _make_synthetic_rpm({k: v for k, v in valid_bin_tags.items() if k != 1122})
        self.assertEqual(inspect_noarch_headers(absent_flags, src_rpm, epoch)["binary_rpm"]["optflags_presence"], "absent")

        # 6. Failure: SRPM epoch mismatch
        bad_src_epoch = _make_synthetic_rpm({**valid_src_tags, 1006: (4, 12345)})
        res_srpm_epoch = inspect_noarch_headers(bin_rpm, bad_src_epoch, epoch)
        self.assertEqual(res_srpm_epoch["status"], "fail")
        self.assertEqual(res_srpm_epoch["reason"], "srpm-buildtime-epoch-mismatch")

        # 7. Failure: SRPM buildhost mismatch
        bad_src_host = _make_synthetic_rpm({**valid_src_tags, 1007: (6, "other-host")})
        res_srpm_host = inspect_noarch_headers(bin_rpm, bad_src_host, epoch)
        self.assertEqual(res_srpm_host["status"], "fail")
        self.assertEqual(res_srpm_host["reason"], "srpm-buildhost-mismatch")

        # 8. Failure: SRPM optflags populated
        bad_src_opt = _make_synthetic_rpm({**valid_src_tags, 1122: (6, "-O2 -g")})
        res_srpm_opt = inspect_noarch_headers(bin_rpm, bad_src_opt, epoch)
        self.assertEqual(res_srpm_opt["status"], "fail")
        self.assertEqual(res_srpm_opt["reason"], "srpm-optflags-non-empty")

        # 9. Parse failure: truncated / invalid header bytes
        corrupt_bin = b"\xed\xab\xee\xdb" + b"\0" * 40
        res_parse = inspect_noarch_headers(corrupt_bin, src_rpm, epoch)
        self.assertEqual(res_parse["status"], "fail")
        self.assertEqual(res_parse["reason"], "binary-rpm-parse-failure")
        self.assertIn("binary-rpm-parse-failure", res_parse["failures"][0])

        corrupt_src = b"\xed\xab\xee\xdb" + b"\0" * 40
        res_src_parse = inspect_noarch_headers(bin_rpm, corrupt_src, epoch)
        self.assertEqual(res_src_parse["status"], "fail")
        self.assertEqual(res_src_parse["reason"], "source-rpm-parse-failure")
        self.assertIn("source-rpm-parse-failure", res_src_parse["failures"][0])

        # Verify all input bytes remain byte-for-byte identical (read-only)
        self.assertEqual(bin_rpm, bin_orig)
        self.assertEqual(src_rpm, src_orig)

    def test_synthetic_lane_gate_records_failure_and_still_runs_dnf(self):
        """[synthetic] rpm-noarch-header-readback gate is required in both RPM lanes and does not suppress DNF on failure."""
        lanes_file = Path(__file__).resolve().parents[1] / "operators/live1/hosted-lanes.json"
        lanes_data = json.loads(lanes_file.read_bytes())
        rpm_lanes = [lane for lane in lanes_data["lanes"] if lane.get("family") == "rpm"]
        self.assertEqual(len(rpm_lanes), 2)
        for lane in rpm_lanes:
            self.assertIn(
                "rpm-noarch-header-readback",
                lane["required_gates"],
                f"Missing gate in lane {lane.get('system')}",
            )

        from rs9.hosted_packaging import rpm_stage_gates
        # Notice record_gates checked for DNF suppression in line 785 only includes rpm_stage_gates:
        stg = rpm_stage_gates(
            ["theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-stellar-burst", "theme-forge-nebular-fusion"],
            {"theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-stellar-burst", "theme-forge-nebular-fusion"},
            {"derivation": {"theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-stellar-burst", "theme-forge-nebular-fusion"},
             "manifest": {"theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-stellar-burst", "theme-forge-nebular-fusion"},
             "custody": {"theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-stellar-burst", "theme-forge-nebular-fusion"}},
            {},
        )
        self.assertTrue(all(g["status"] == "pass" for g in stg))
        # Note that rpm-noarch-header-readback is intentionally separate from record_gates so DNF runs even if header readback fails.
        self.assertNotIn("rpm-noarch-header-readback", [g["name"] for g in stg])
        from rs9.hosted_packaging import noarch_header_gate
        from rs9.hosted_summary import gate_blockers
        self.assertEqual(noarch_header_gate({})["status"], "fail")
        witnesses = {}
        for pid in ("theme-forge-stellar-loom", "theme-forge-solar-sail"):
            witnesses[pid] = {"package_sha256": "a" * 64, "spec_sha256": "b" * 64,
                "reproducibility": {"source_rpm": {"sha256": "c" * 64}, "npm_closure_sha256": "d" * 64},
                "finished_header": {"status": "pass", "identities": {"package_sha256": "a" * 64,
                    "spec_sha256": "b" * 64, "source_rpm_sha256": "c" * 64, "closure_sha256": "d" * 64}}}
        self.assertEqual(noarch_header_gate(witnesses)["status"], "pass")
        witnesses["theme-forge-solar-sail"]["finished_header"]["identities"]["spec_sha256"] = "e" * 64
        self.assertEqual(noarch_header_gate(witnesses)["status"], "fail")
        lane = {"required_gates": ["rpm-noarch-header-readback"]}
        self.assertIn("missing-or-duplicate-gate:rpm-noarch-header-readback", gate_blockers(lane, {"gates": []}))
        self.assertIn("not-run:rpm-noarch-header-readback", gate_blockers(lane, {"gates": [{"name": "rpm-noarch-header-readback", "status": "not-run"}]}))

    def test_synthetic_execute_continues_dnf_with_failed_finished_header(self):
        """Exercise the actual lane orchestration; native tools are explicit doubles."""
        from rs9 import hosted_packaging as hp
        from tests.rpm_summary_fixtures import witnessed_build_double
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary).resolve()
            lane = root / "lane"; lane.mkdir()
            products = ("theme-forge-stellar-burst", "theme-forge-stellar-loom", "theme-forge-solar-sail", "theme-forge-nebular-fusion")
            captures = [(SimpleNamespace(root=root / p), {"project": {"id": p}}, {}) for p in products]
            context = {"family": "rpm", "system": "x86_64-linux", "repository": root, "scratch": lane,
                       "pins": {}, "captures": captures, "client": None,
                       "binding": {"source_commit": "0" * 40}, "authentication_sha256": "1" * 64}
            environment = {"platform": "linux/amd64", "image_ref": "fedora@sha256:" + "a" * 64, "preprovisioned_packages": []}
            def build(capture, intent, arch, work, **kwargs):
                pid = intent["project"]["id"]
                package = work / (pid + ".rpm"); package.write_bytes(pid.encode())
                spec = work / "rpmbuild/SPECS" / (pid + ".spec")
                spec.parent.mkdir(parents=True); spec.write_bytes(b"synthetic spec")
                (work / "rpm-manifest.json").write_bytes(b"{}")
                return {"rpm_path": package, "policy_evaluation": {"synthetic": True},
                        "manifest": {"rpm_identity": {"name": pid, "version": "1", "release": "1", "arch": arch},
                                     "rpm_payload_digest": {"payload_digest": "a" * 64}}}
            fixture = SimpleNamespace(primary_fingerprint="A" * 40, homedir=root)
            scope = mock.MagicMock(); scope.__enter__.return_value = (fixture, fixture)
            for name, value in (("provision", environment), ("prepare_client", {"status": "pass"}),
                                ("verify_client_image", "sha256:" + "a" * 64), ("container_tool_facts", {}),
                                ("_resolve_offline_npm_archives", None), ("_fixture_scope", scope),
                                ("write_keys", None), ("sign_rpm", {}), ("_verify_unsigned_products", None)):
                stack.enter_context(mock.patch.object(hp, name, return_value=value))
            stack.enter_context(mock.patch("rs9.rpm_client_runtime.bind_engine_floors", side_effect=lambda runtime, _: runtime))
            stack.enter_context(mock.patch("rs9.hosted_deb.provision_image"))
            stack.enter_context(mock.patch.object(hp, "checked", return_value=CommandReceipt(["fixture"], 0, b"", b"", executed=False)))
            stack.enter_context(mock.patch.object(hp, "build_rpm_candidate", side_effect=witnessed_build_double(build)))
            stack.enter_context(mock.patch("rs9.rpm_evidence.write_policy_evidence", return_value=({"accepted": True}, [])))
            stack.enter_context(mock.patch("rs9.rpm_repository.sign_metadata", return_value={"status": "pass"}))
            stack.enter_context(mock.patch("rs9.rpm_repository.audit_owned_tree", return_value={"status": "pass"}))
            stack.enter_context(mock.patch("rs9.hosted_smoke.prepare_smoke", return_value={}))
            stack.enter_context(mock.patch("rs9.hosted_deb._burst_release_record", return_value={}))
            client = stack.enter_context(mock.patch("rs9.hosted_deb.client_cycle", return_value=([], {})))
            negatives = stack.enter_context(mock.patch("rs9.hosted_deb.tamper_cycle", return_value=[]))
            result = hp.execute(context)
            self.assertEqual(next(g for g in result["gates"] if g["name"] == "rpm-noarch-header-readback")["status"], "fail")
            client.assert_called_once()
            negatives.assert_called_once()

    def test_reference_readback_with_run12_references(self):
        """Reference readback of exact 8 unsigned noarch RPMs from kit if available."""
        ref_dir_env = os.environ.get("RS9_RUN12_REFERENCE_DIR")
        if not ref_dir_env:
            self.skipTest("RUN12 reference directory not supplied")
        ref_dir = Path(ref_dir_env)

        products = ["theme-forge-stellar-loom-0.4.0-1.fc43", "theme-forge-solar-sail-0.2.1-1.fc43"]
        for name in products:
            bin_x86 = (ref_dir / "x86_64-linux" / f"{name}.noarch.rpm").read_bytes()
            bin_arm = (ref_dir / "aarch64-linux" / f"{name}.noarch.rpm").read_bytes()
            src_x86 = (ref_dir / "x86_64-linux" / f"{name}.src.rpm").read_bytes()
            src_arm = (ref_dir / "aarch64-linux" / f"{name}.src.rpm").read_bytes()

            # SRPM equality verified
            self.assertEqual(src_x86, src_arm)
            self.assertEqual(header_delta(src_x86, src_arm), [])

            # Binary delta is strictly [1122] (OPTFLAGS)
            self.assertNotEqual(bin_x86, bin_arm)
            delta = header_delta(bin_x86, bin_arm)
            self.assertEqual(delta, [1122])

            # Compressed payloads are equal
            _, _, p_x86 = inspect_rpm(bin_x86)
            _, _, p_arm = inspect_rpm(bin_arm)
            self.assertEqual(p_x86, p_arm)

            # Header readback fails closed on RUN12 binary RPMs due to optflags defect
            readback = inspect_noarch_headers(bin_x86, src_x86, 1790640000, expected_buildhost="starport-buildhost-live1-deterministic.invalid")
            self.assertEqual(readback["status"], "fail")
            self.assertTrue(any("optflags-non-empty" in f for f in readback["failures"]))


if __name__ == "__main__":
    unittest.main()
