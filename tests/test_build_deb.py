"""Tests for Debian / Ubuntu 26.04 candidate package driver, dpkg-shlibdeps derivation, and APT repository candidate."""

from __future__ import annotations

import copy
import gzip
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from rs9.build_deb import (
    DEB_NATIVE_REQUIRED_TOOLS,
    DEB_REQUIRED_TOOLS,
    ELF_MACHINE,
    SOURCE_DATE_EPOCH,
    build_deb_candidate,
    collect_elf_inventory,
    derive_native_dependencies,
    main as deb_main,
    validate_deb_ar_shape,
)
from tests.elf_builder import build_elf
from rs9.build_native import (
    CommandReceipt,
    MockCommandRunner,
    NativePrerequisiteUnavailable,
    check_prerequisites,
    validate_scratch_root,
)
from rs9.errors import ContractError
from rs9.profiles import selection_for_intent
from rs9.release_core import authenticate_release, digest
from rs9.repo_apt import validate_apt_repository
from rs9.scratch import canonical
from tests.publication_fixtures import authorize_fixture_configuration
from tests.shadow_fixtures import fixture_evidence, tar_bytes
from tests.test_build_native import create_cli_fixture


def make_minimal_deb(
    package: str,
    version: str,
    revision: int,
    arch: str,
    maintainer: str,
    description: str,
    depends: str,
) -> bytes:
    """Create a minimal valid debian ar archive matching parse_deb_control specifications."""
    control_content = (
        f"Package: {package}\n"
        f"Version: {version}-{revision}\n"
        f"Architecture: {arch}\n"
        f"Maintainer: {maintainer}\n"
        f"Depends: {depends}\n"
        f"Section: utils\n"
        f"Priority: optional\n"
        f"Description: {description}\n"
    ).encode("utf-8")

    # control.tar.xz
    ctrl_buf = io.BytesIO()
    with tarfile.open(fileobj=ctrl_buf, mode="w:xz") as tar:
        ti = tarfile.TarInfo("./control")
        ti.size = len(control_content)
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(control_content))
    ctrl_data = ctrl_buf.getvalue()

    # data.tar.xz
    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w:xz") as tar:
        ti = tarfile.TarInfo(f"./usr/lib/{package}/NOTICE")
        payload = b"Theme Forge Notice\n"
        ti.size = len(payload)
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(payload))
    data_bytes = data_buf.getvalue()

    # debian-binary
    bin_data = b"2.0\n"

    def ar_entry(name: str, data: bytes) -> bytes:
        header = f"{name:<16}0           0     0     100644  {len(data):<10}`\n".encode("ascii")
        pad = b"\n" if len(data) % 2 != 0 else b""
        return header + data + pad

    return (
        b"!<arch>\n"
        + ar_entry("debian-binary", bin_data)
        + ar_entry("control.tar.xz", ctrl_data)
        + ar_entry("data.tar.xz", data_bytes)
    )


class BuildDebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_scratch_root_validation(self):
        scratch = self.root / "scratch"
        scratch.mkdir()
        self.assertEqual(validate_scratch_root(scratch), scratch)

        (scratch / "occupied").write_bytes(b"data")
        with self.assertRaises(ContractError) as caught:
            validate_scratch_root(scratch)
        self.assertEqual(caught.exception.code, "OUTPUT_NOT_EMPTY")

    def test_maintainer_explicit_requirement_and_injection_rejection(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input")
        scratch = self.root / "scratch"
        scratch.mkdir()

        runner = MockCommandRunner(
            available_tools={"dpkg-deb": "/usr/bin/dpkg-deb", "dpkg-shlibdeps": "/usr/bin/dpkg-shlibdeps"}
        )

        # Missing maintainer fails closed
        with self.assertRaises(ContractError) as caught_none:
            build_deb_candidate(capture, intent, "all", scratch, maintainer=None, runner=runner)
        self.assertEqual(caught_none.exception.code, "MISSING_MAINTAINER")

        # Empty maintainer fails closed
        with self.assertRaises(ContractError) as caught_empty:
            build_deb_candidate(capture, intent, "all", scratch, maintainer="   ", runner=runner)
        self.assertEqual(caught_empty.exception.code, "MISSING_MAINTAINER")

        # Invalid maintainer format (no email)
        with self.assertRaises(ContractError) as caught_noemail:
            build_deb_candidate(capture, intent, "all", scratch, maintainer="Just A Name", runner=runner)
        self.assertEqual(caught_noemail.exception.code, "INVALID_METADATA")

        # Injection attempt with newline fails
        with self.assertRaises(ContractError) as caught_inject:
            build_deb_candidate(
                capture, intent, "all", scratch,
                maintainer="Valid Name <email@example.com>\nInjected: line",
                runner=runner,
            )
        self.assertEqual(caught_inject.exception.code, "INVALID_METADATA")

    def test_distro_scope_strictly_ubuntu2604_resolute(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input")
        scratch = self.root / "scratch"
        scratch.mkdir()

        runner = MockCommandRunner(available_tools={"dpkg-deb": "/usr/bin/dpkg-deb"})
        maintainer = "Theme Forge Lead <maintainer@example.com>"

        # Debian distributions are explicitly rejected
        for bad_dist in ("debian", "debian-13", "debian13", "trixie", "bookworm"):
            with self.subTest(distro=bad_dist), self.assertRaises(ContractError) as caught:
                build_deb_candidate(
                    capture, intent, "all", scratch,
                    maintainer=maintainer,
                    distro=bad_dist,
                    runner=runner,
                )
            self.assertEqual(caught.exception.code, "UNSUPPORTED_PLATFORM")

    def test_architecture_truthfulness_native_and_cli(self):
        # Native Nebular
        neb_dir = self.root / "nebular"
        neb_dir.mkdir()
        intent_neb = fixture_evidence(neb_dir)
        capture_neb = authenticate_release(selection_for_intent(intent_neb), neb_dir)
        authorize_fixture_configuration(neb_dir, intent_neb, capture_neb)

        maintainer = "Theme Forge Lead <maintainer@example.com>"
        runner = MockCommandRunner(
            available_tools={"dpkg-deb": "/usr/bin/dpkg-deb", "dpkg-shlibdeps": "/usr/bin/dpkg-shlibdeps"}
        )

        scratch_neb = self.root / "scratch_neb"
        scratch_neb.mkdir()

        # Nebular accepts amd64/arm64, rejects 'all' and 'x86_64'
        with self.assertRaises(ContractError) as caught_all:
            build_deb_candidate(capture_neb, intent_neb, "all", scratch_neb, maintainer=maintainer, runner=runner)
        self.assertEqual(caught_all.exception.code, "INVALID_ARCHITECTURE")

        with self.assertRaises(ContractError) as caught_x86:
            build_deb_candidate(capture_neb, intent_neb, "x86_64", scratch_neb, maintainer=maintainer, runner=runner)
        self.assertEqual(caught_x86.exception.code, "INVALID_ARCHITECTURE")

        # CLI Loom accepts 'all', rejects 'amd64'
        capture_cli, intent_cli, _ = create_cli_fixture(self.root / "loom_input")
        scratch_cli = self.root / "scratch_cli"
        scratch_cli.mkdir()

        with self.assertRaises(ContractError) as caught_cli_amd:
            build_deb_candidate(capture_cli, intent_cli, "amd64", scratch_cli, maintainer=maintainer, runner=runner)
        self.assertEqual(caught_cli_amd.exception.code, "INVALID_ARCHITECTURE")

    @patch("rs9.build_native.shutil.which", return_value=None)
    def test_prerequisites_absent_explicit_unavailable_never_fabricated(self, _which):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input")
        scratch = self.root / "scratch"
        scratch.mkdir()

        maintainer = "Theme Forge Lead <maintainer@example.com>"
        with self.assertRaises(NativePrerequisiteUnavailable) as caught:
            build_deb_candidate(capture, intent, "all", scratch, maintainer=maintainer)
        self.assertEqual(caught.exception.code, "TOOL_UNAVAILABLE")
        # Ensure no fabricated candidate files were created
        self.assertEqual(list(scratch.iterdir()), [])

    def test_native_launcher_only_derivation_is_withheld(self):
        neb_dir = self.root / "nebular"
        neb_dir.mkdir()
        intent = fixture_evidence(neb_dir)
        capture = authenticate_release(selection_for_intent(intent), neb_dir)
        authorize_fixture_configuration(neb_dir, intent, capture)
        scratch = self.root / "native_scratch"
        scratch.mkdir()
        runner = MockCommandRunner(available_tools={"dpkg-deb": "/usr/bin/dpkg-deb",
                                                   "dpkg-shlibdeps": "/usr/bin/dpkg-shlibdeps"})
        with self.assertRaises(ContractError) as caught:
            build_deb_candidate(capture, intent, "amd64", scratch,
                                maintainer="Fixture Maintainer <fixture@example.com>", runner=runner)
        self.assertEqual(caught.exception.code, "NATIVE_DEPENDENCY_DERIVATION_UNQUALIFIED")
        self.assertFalse(list(scratch.glob("*.deb")))

    def test_cli_deb_build_and_npm_closure(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input")
        scratch = self.root / "scratch_deb_cli"
        scratch.mkdir()
        maintainer = "Theme Forge Lead <maintainer@example.com>"

        def dpkg_deb_handler(argv, cwd=None, env=None):
            out_deb = Path(argv[-1])
            deb_bytes = make_minimal_deb(
                "theme-forge-stellar-loom",
                "0.4.0",
                1,
                "all",
                maintainer,
                "Synthetic Loom summary",
                "nodejs (>= 22)",
            )
            out_deb.write_bytes(deb_bytes)
            return CommandReceipt(argv, 0, b"dpkg-deb: building package ...\n", b"")

        runner = MockCommandRunner(
            available_tools={"dpkg-deb": "/usr/bin/dpkg-deb"},
            handlers={"dpkg-deb": dpkg_deb_handler},
        )

        result = build_deb_candidate(
            capture,
            intent,
            "all",
            scratch,
            maintainer=maintainer,
            offline_npm_archives=offline_npm,
            runner=runner,
        )

        manifest = result["manifest"]
        derivation = result["derivation_record"]

        self.assertEqual(manifest["architecture"], "all")
        self.assertEqual(manifest["dependencies"], "nodejs (>= 22)")
        self.assertEqual(manifest["dependency_classification"], "reviewed-policy")
        self.assertFalse(manifest["can_publish"])
        self.assertEqual(derivation["derived_dependencies"], ["nodejs (>= 22)"])
        self.assertEqual(derivation["dependency_classification"], "reviewed-policy")
        self.assertFalse(derivation["can_publish"])

        # Check installed wrapper script
        wrapper_path = scratch / "pkg/theme-forge-stellar-loom_0.4.0-1_all/usr/bin/tfsl"
        self.assertTrue(wrapper_path.exists())
        wrapper_text = wrapper_path.read_text("utf-8")
        self.assertIn('exec node "/usr/lib/theme-forge-stellar-loom/bin/run.js"', wrapper_text)

        # Check APT repository indexing and validation
        self.assertIn("apt_repository", manifest)
        repo_val = manifest["apt_repository"]
        self.assertEqual(repo_val["distribution"], "resolute")
        self.assertEqual(repo_val["verified_packages"], 1)
        self.assertEqual(repo_val["verified_indices"], 6)

        repo_root = scratch / "apt_repo"
        release_path = repo_root / "dists/resolute/Release"
        self.assertTrue(release_path.is_file())
        release_text = release_path.read_text("utf-8")
        self.assertIn("Architectures: amd64 arm64", release_text)
        self.assertIn("main/binary-amd64/Packages", release_text)
        self.assertIn("main/binary-arm64/Packages", release_text)

        amd64_pkgs = (repo_root / "dists/resolute/main/binary-amd64/Packages").read_text("utf-8")
        arm64_pkgs = (repo_root / "dists/resolute/main/binary-arm64/Packages").read_text("utf-8")
        self.assertIn("Package: theme-forge-stellar-loom", amd64_pkgs)
        self.assertIn("Architecture: all", amd64_pkgs)
        self.assertIn("Package: theme-forge-stellar-loom", arm64_pkgs)
        self.assertIn("Architecture: all", arm64_pkgs)

        pool_deb = repo_root / "pool/main/t/theme-forge-stellar-loom/theme-forge-stellar-loom_0.4.0-1_all.deb"
        self.assertTrue(pool_deb.is_file())
        self.assertEqual(pool_deb.read_bytes(), result["deb_path"].read_bytes())

    def test_cli_deb_rejects_native_binary_in_asset(self):
        capture, intent, offline_npm = create_cli_fixture(
            self.root / "bad_asset_elf",
            extra_asset_entries=[("bin/native_bin", b"\x7fELF" + b"\x00" * 20)],
        )
        scratch = self.root / "scratch_bad_asset"
        scratch.mkdir()
        runner = MockCommandRunner(available_tools={"dpkg-deb": "/usr/bin/dpkg-deb"})
        with self.assertRaises(ContractError) as caught:
            build_deb_candidate(
                capture, intent, "all", scratch,
                maintainer="Theme Forge Lead <maintainer@example.com>",
                offline_npm_archives=offline_npm,
                runner=runner,
            )
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_cli_deb_rejects_macho_in_asset(self):
        capture, intent, offline_npm = create_cli_fixture(
            self.root / "bad_asset_macho",
            extra_asset_entries=[("bin/macho_bin", b"\xcf\xfa\xed\xfe" + b"\x00" * 20)],
        )
        scratch = self.root / "scratch_macho"
        scratch.mkdir()
        runner = MockCommandRunner(available_tools={"dpkg-deb": "/usr/bin/dpkg-deb"})
        with self.assertRaises(ContractError) as caught:
            build_deb_candidate(
                capture, intent, "all", scratch,
                maintainer="Theme Forge Lead <maintainer@example.com>",
                offline_npm_archives=offline_npm,
                runner=runner,
            )
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_cli_deb_rejects_pe_in_asset(self):
        capture, intent, offline_npm = create_cli_fixture(
            self.root / "bad_asset_pe",
            extra_asset_entries=[("bin/tool.exe", b"MZ" + b"\x00" * 20)],
        )
        scratch = self.root / "scratch_pe"
        scratch.mkdir()
        runner = MockCommandRunner(available_tools={"dpkg-deb": "/usr/bin/dpkg-deb"})
        with self.assertRaises(ContractError) as caught:
            build_deb_candidate(
                capture, intent, "all", scratch,
                maintainer="Theme Forge Lead <maintainer@example.com>",
                offline_npm_archives=offline_npm,
                runner=runner,
            )
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_cli_deb_rejects_native_node_addon_in_npm_closure(self):
        capture, intent, offline_npm = create_cli_fixture(
            self.root / "bad_dep_node",
            extra_dep_entries=[("binding.node", b"\x00" * 16)],
        )
        scratch = self.root / "scratch_dep_node"
        scratch.mkdir()
        runner = MockCommandRunner(available_tools={"dpkg-deb": "/usr/bin/dpkg-deb"})
        with self.assertRaises(ContractError) as caught:
            build_deb_candidate(
                capture, intent, "all", scratch,
                maintainer="Theme Forge Lead <maintainer@example.com>",
                offline_npm_archives=offline_npm,
                runner=runner,
            )
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_cli_deb_rejects_shared_library_in_npm_closure(self):
        capture, intent, offline_npm = create_cli_fixture(
            self.root / "bad_dep_so",
            extra_dep_entries=[("lib/libfoo.so", b"\x7fELF" + b"\x00" * 16)],
        )
        scratch = self.root / "scratch_dep_so"
        scratch.mkdir()
        runner = MockCommandRunner(available_tools={"dpkg-deb": "/usr/bin/dpkg-deb"})
        with self.assertRaises(ContractError) as caught:
            build_deb_candidate(
                capture, intent, "all", scratch,
                maintainer="Theme Forge Lead <maintainer@example.com>",
                offline_npm_archives=offline_npm,
                runner=runner,
            )
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_cli_deb_rejects_dylib_in_npm_closure(self):
        capture, intent, offline_npm = create_cli_fixture(
            self.root / "bad_dep_dylib",
            extra_dep_entries=[("lib/libmac.dylib", b"\xca\xfe\xba\xbe" + b"\x00" * 16)],
        )
        scratch = self.root / "scratch_dep_dylib"
        scratch.mkdir()
        runner = MockCommandRunner(available_tools={"dpkg-deb": "/usr/bin/dpkg-deb"})
        with self.assertRaises(ContractError) as caught:
            build_deb_candidate(
                capture, intent, "all", scratch,
                maintainer="Theme Forge Lead <maintainer@example.com>",
                offline_npm_archives=offline_npm,
                runner=runner,
            )
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_cli_deb_rejects_platform_restricted_npm_dependency(self):
        capture, intent, offline_npm = create_cli_fixture(
            self.root / "bad_dep_restricted",
            dep_pkg_json_override={"name": "min-dep", "version": "1.0.0", "license": "MIT", "os": ["darwin"]},
        )
        scratch = self.root / "scratch_dep_restricted"
        scratch.mkdir()
        runner = MockCommandRunner(available_tools={"dpkg-deb": "/usr/bin/dpkg-deb"})
        with self.assertRaises(ContractError) as caught:
            build_deb_candidate(
                capture, intent, "all", scratch,
                maintainer="Theme Forge Lead <maintainer@example.com>",
                offline_npm_archives=offline_npm,
                runner=runner,
            )
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    @patch("rs9.build_native.shutil.which", return_value=None)
    def test_deb_cli_command_driver(self, _which):
        code = deb_main(["--arch", "all", "--capture", "c", "--intent", "i", "--scratch", "s", "--maintainer", "m", "--check-prerequisites"])
        self.assertEqual(code, 1)

    def test_cli_deb_is_clamped_to_source_date_epoch_and_proves_no_elf(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input")
        scratch = self.root / "scratch_epoch"
        scratch.mkdir()
        maintainer = "Theme Forge Lead <maintainer@example.com>"
        seen = {}

        def dpkg_deb_handler(argv, cwd=None, env=None):
            seen["env"] = env
            seen["argv"] = argv
            Path(argv[-1]).write_bytes(make_minimal_deb(
                "theme-forge-stellar-loom", "0.4.0", 1, "all", maintainer, "Synthetic Loom summary", "nodejs (>= 22)"))
            return CommandReceipt(argv, 0, b"", b"")

        runner = MockCommandRunner(available_tools={"dpkg-deb": "/usr/bin/dpkg-deb"},
                                   handlers={"dpkg-deb": dpkg_deb_handler})
        result = build_deb_candidate(capture, intent, "all", scratch, maintainer=maintainer,
                                     offline_npm_archives=offline_npm, runner=runner)
        self.assertEqual(seen["env"], {"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH})
        expected_cmd = [
            "dpkg-deb",
            "--build",
            "--root-owner-group",
            "-Zxz",
            "-z6",
            "--uniform-compression",
            "--threads-max=1",
            str(scratch / "pkg/theme-forge-stellar-loom_0.4.0-1_all"),
            str(scratch / "theme-forge-stellar-loom_0.4.0-1_all.deb"),
        ]
        self.assertEqual(seen["argv"], expected_cmd)
        self.assertEqual(result["manifest"]["elf_object_count"], 0)
        self.assertIsNone(result["manifest"]["shlibs_inventory"])
        evidence = result["derivation_record"]["evidence"]
        self.assertFalse(evidence["dpkg_shlibdeps_executed"])
        self.assertEqual(evidence["elf_objects"], [])
        self.assertEqual(result["derivation_record"]["derivation_source"], "reviewed-policy")

    def test_validate_deb_ar_shape_closed_exact_structure(self):
        sample_xz_buf = io.BytesIO()
        with tarfile.open(fileobj=sample_xz_buf, mode="w:xz") as tar:
            pass
        valid_xz = sample_xz_buf.getvalue()

        def make_ar(entries: list[tuple[str, bytes]]) -> bytes:
            out = io.BytesIO()
            out.write(b"!<arch>\n")
            for name, content in entries:
                header = f"{name:<16}0           0     0     100644  {len(content):<10}`\n".encode("ascii")
                pad = b"\n" if len(content) % 2 != 0 else b""
                out.write(header + content + pad)
            return out.getvalue()

        # Valid shape: exactly debian-binary=2.0\n, control.tar.xz, data.tar.xz
        valid_deb = make_ar([
            ("debian-binary", b"2.0\n"),
            ("control.tar.xz", valid_xz),
            ("data.tar.xz", valid_xz),
        ])
        validate_deb_ar_shape(valid_deb)

        # Non-ar archive rejected
        with self.assertRaises(ContractError) as caught:
            validate_deb_ar_shape(b"not an ar archive")
        self.assertEqual(caught.exception.code, "INVALID_DEB")

        # debian-binary with non-2.0\n content rejected
        bad_bin = make_ar([
            ("debian-binary", b"1.0\n"),
            ("control.tar.xz", valid_xz),
            ("data.tar.xz", valid_xz),
        ])
        with self.assertRaises(ContractError) as caught:
            validate_deb_ar_shape(bad_bin)
        self.assertEqual(caught.exception.code, "INVALID_DEB")

        # Second member control.tar.gz rejected
        gz_ctrl = make_ar([
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", b"gzip-bytes"),
            ("data.tar.xz", valid_xz),
        ])
        with self.assertRaises(ContractError) as caught:
            validate_deb_ar_shape(gz_ctrl)
        self.assertEqual(caught.exception.code, "INVALID_DEB")

        # Second member control.tar.zst rejected
        zst_ctrl = make_ar([
            ("debian-binary", b"2.0\n"),
            ("control.tar.zst", b"zstd-bytes"),
            ("data.tar.xz", valid_xz),
        ])
        with self.assertRaises(ContractError) as caught:
            validate_deb_ar_shape(zst_ctrl)
        self.assertEqual(caught.exception.code, "INVALID_DEB")

        # Third member data.tar.gz rejected
        gz_data = make_ar([
            ("debian-binary", b"2.0\n"),
            ("control.tar.xz", valid_xz),
            ("data.tar.gz", b"gzip-bytes"),
        ])
        with self.assertRaises(ContractError) as caught:
            validate_deb_ar_shape(gz_data)
        self.assertEqual(caught.exception.code, "INVALID_DEB")

        # Non-xz control stream rejected
        non_xz_ctrl = make_ar([
            ("debian-binary", b"2.0\n"),
            ("control.tar.xz", b"not-an-xz-stream"),
            ("data.tar.xz", valid_xz),
        ])
        with self.assertRaises(ContractError) as caught:
            validate_deb_ar_shape(non_xz_ctrl)
        self.assertEqual(caught.exception.code, "INVALID_DEB")

        # Non-xz data stream rejected
        non_xz_data = make_ar([
            ("debian-binary", b"2.0\n"),
            ("control.tar.xz", valid_xz),
            ("data.tar.xz", b"not-an-xz-stream"),
        ])
        with self.assertRaises(ContractError) as caught:
            validate_deb_ar_shape(non_xz_data)
        self.assertEqual(caught.exception.code, "INVALID_DEB")

        # Missing data member (only 2 members) rejected
        two_members = make_ar([
            ("debian-binary", b"2.0\n"),
            ("control.tar.xz", valid_xz),
        ])
        with self.assertRaises(ContractError) as caught:
            validate_deb_ar_shape(two_members)
        self.assertEqual(caught.exception.code, "INVALID_DEB")

        # Extra member (4 members) rejected
        four_members = make_ar([
            ("debian-binary", b"2.0\n"),
            ("control.tar.xz", valid_xz),
            ("data.tar.xz", valid_xz),
            ("extra.tar.xz", valid_xz),
        ])
        with self.assertRaises(ContractError) as caught:
            validate_deb_ar_shape(four_members)
        self.assertEqual(caught.exception.code, "INVALID_DEB")

        # Trailing garbage rejected
        with self.assertRaises(ContractError) as caught:
            validate_deb_ar_shape(valid_deb + b"trailing-garbage")
        self.assertEqual(caught.exception.code, "INVALID_DEB")

    def test_build_deb_candidate_post_build_shape_rejects_non_xz_deb(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input")
        scratch = self.root / "scratch_post_build_bad"
        scratch.mkdir()
        maintainer = "Theme Forge Lead <maintainer@example.com>"

        # Mock runner writes a deb with control.tar.gz instead of control.tar.xz
        def dpkg_deb_bad_handler(argv, cwd=None, env=None):
            def ar_entry(name, data):
                header = f"{name:<16}0           0     0     100644  {len(data):<10}`\n".encode("ascii")
                pad = b"\n" if len(data) % 2 != 0 else b""
                return header + data + pad
            bad_deb = (
                b"!<arch>\n"
                + ar_entry("debian-binary", b"2.0\n")
                + ar_entry("control.tar.gz", b"synthetic-gzip-control")
                + ar_entry("data.tar.gz", b"synthetic-gzip-data")
            )
            Path(argv[-1]).write_bytes(bad_deb)
            return CommandReceipt(argv, 0, b"", b"")

        runner = MockCommandRunner(
            available_tools={"dpkg-deb": "/usr/bin/dpkg-deb"},
            handlers={"dpkg-deb": dpkg_deb_bad_handler},
        )
        with self.assertRaises(ContractError) as caught:
            build_deb_candidate(
                capture, intent, "all", scratch,
                maintainer=maintainer,
                offline_npm_archives=offline_npm,
                runner=runner,
            )
        self.assertEqual(caught.exception.code, "INVALID_DEB")


class NativeDependencyDerivationTests(unittest.TestCase):
    MAINTAINER = "Theme Forge Lead <maintainer@example.com>"
    DEPENDS = "libc6 (>= 2.34), libgtk-3-0t64 (>= 3.24)"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.calls = {"shlibdeps": [], "query": [], "deb": []}

    def native(self, extra_linux=()):
        directory = self.root / f"nebular-{len(list(self.root.iterdir()))}"
        directory.mkdir()
        intent = fixture_evidence(directory, extra_linux=extra_linux)
        capture = authenticate_release(selection_for_intent(intent), directory)
        authorize_fixture_configuration(directory, intent, capture)
        return capture, intent

    def runner(self, *, shlibdeps=None, query=None, tools=("dpkg-deb", "dpkg-shlibdeps", "dpkg-query")):
        def deb(argv, cwd=None, env=None):
            self.calls["deb"].append(env)
            Path(argv[-1]).write_bytes(make_minimal_deb(
                "theme-forge-nebular-fusion", "0.6.1", 1, "amd64", self.MAINTAINER, "Synthetic Nebular", self.DEPENDS))
            return CommandReceipt(argv, 0, b"", b"")

        def default_shlibdeps(argv, cwd=None, env=None):
            self.calls["shlibdeps"].append((argv, cwd))
            return CommandReceipt(argv, 0, f"shlibs:Depends={self.DEPENDS}\n".encode(), b"")

        def default_query(argv, cwd=None, env=None):
            self.calls["query"].append(argv)
            return CommandReceipt(argv, 0, b"libc6\t2.43-1\tamd64\nlibgtk-3-0t64:amd64\t3.24.43\tamd64\n", b"")

        return MockCommandRunner(
            available_tools={tool: f"/usr/bin/{tool}" for tool in tools},
            handlers={"dpkg-deb": deb, "dpkg-shlibdeps": shlibdeps or default_shlibdeps,
                      "dpkg-query": query or default_query})

    def build(self, runner, **kwargs):
        capture, intent = self.native(**kwargs)
        scratch = self.root / f"scratch-{len(list(self.root.iterdir()))}"
        scratch.mkdir()
        return scratch, lambda: build_deb_candidate(
            capture, intent, "amd64", scratch, maintainer=self.MAINTAINER, runner=runner)

    def test_native_dependencies_come_only_from_dpkg_shlibdeps_over_every_elf(self):
        scratch, run = self.build(self.runner())
        result = run()
        manifest, derivation = result["manifest"], result["derivation_record"]
        self.assertEqual(manifest["architecture"], "amd64")
        self.assertEqual(manifest["dependencies"], self.DEPENDS)
        self.assertEqual(manifest["dependency_classification"], "native-tool-derived")
        self.assertEqual(manifest["elf_object_count"], 1)
        self.assertEqual(derivation["dependency_classification"], "native-tool-derived")
        self.assertEqual(derivation["derived_dependencies"], sorted(self.DEPENDS.split(", ")))
        # A mock seam is labelled synthetic; only a real subprocess may claim an actual derivation.
        self.assertEqual(derivation["derivation_source"], "synthetic-command-seam")
        evidence = derivation["evidence"]
        self.assertTrue(evidence["dpkg_shlibdeps_executed"])
        self.assertEqual([row["machine"] for row in evidence["elf_objects"]], ["x86_64"])
        self.assertEqual(evidence["elf_objects"][0]["needed"], ["libc.so.6"])
        self.assertEqual([row["name"] for row in evidence["shlibs_inventory"]["packages"]], ["libc6", "libgtk-3-0t64:amd64"])

        (argv, cwd), = self.calls["shlibdeps"]
        self.assertEqual(argv[:2], ["dpkg-shlibdeps", "-O"])
        exe_args = [a for a in argv if a.startswith("-e")]
        self.assertEqual(len(exe_args), manifest["elf_object_count"])
        self.assertTrue(exe_args[0].endswith("/usr/lib/theme-forge-nebular-fusion/bin/theme-forge-nebular-fusion"))
        control = (Path(cwd) / "debian/control").read_text("utf-8")
        self.assertIn("Package: theme-forge-nebular-fusion", control)
        self.assertIn("Architecture: amd64", control)
        (query,) = self.calls["query"]
        self.assertEqual(query[:2], ["dpkg-query", "-W"])
        # Query the derived names; dpkg-query reports the installed multiarch identity.
        self.assertEqual(query[3:], ["libc6", "libgtk-3-0t64"])
        self.assertEqual(self.calls["deb"], [{"SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH}])

        pkg = scratch / "pkg/theme-forge-nebular-fusion_0.6.1-1_amd64"
        self.assertIn(f"Depends: {self.DEPENDS}", (pkg / "DEBIAN/control").read_text("utf-8"))
        link = pkg / "usr/bin/tfnf"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "../lib/theme-forge-nebular-fusion/bin/tfnf")
        self.assertTrue((pkg / "usr/share/applications/theme-forge-nebular-fusion.desktop").is_file())
        self.assertTrue((pkg / "usr/share/icons/hicolor/256x256/apps/theme-forge-nebular-fusion.png").is_file())
        self.assertEqual(result["manifest"]["apt_repository"]["verified_packages"], 1)

    def test_shlibdeps_failure_withholds_the_native_package(self):
        def failing(argv, cwd=None, env=None):
            return CommandReceipt(argv, 2, b"", b"dpkg-shlibdeps: error: cannot find library")

        scratch, run = self.build(self.runner(shlibdeps=failing))
        with self.assertRaises(ContractError) as caught:
            run()
        self.assertEqual(caught.exception.code, "NATIVE_DEPENDENCY_DERIVATION_FAILED")
        self.assertEqual(list(scratch.glob("*.deb")), [])

    def test_derived_package_missing_from_installed_inventory_is_unqualified(self):
        def partial(argv, cwd=None, env=None):
            return CommandReceipt(argv, 0, b"libc6\t2.43-1\tamd64\n", b"")

        _, run = self.build(self.runner(query=partial))
        with self.assertRaises(ContractError) as caught:
            run()
        self.assertEqual(caught.exception.code, "NATIVE_DEPENDENCY_DERIVATION_UNQUALIFIED")

        def failing(argv, cwd=None, env=None):
            return CommandReceipt(argv, 1, b"libc6\t2.43-1\tamd64\nlibgtk-3-0t64\t3.24\tamd64\n", b"")

        _, run = self.build(self.runner(query=failing))
        with self.assertRaises(ContractError) as caught:
            run()
        self.assertEqual(caught.exception.code, "NATIVE_DEPENDENCY_DERIVATION_UNQUALIFIED")

    def test_missing_dpkg_query_is_explicit_unavailable_not_a_fabricated_inventory(self):
        _, run = self.build(self.runner(tools=("dpkg-deb", "dpkg-shlibdeps")))
        with self.assertRaises(NativePrerequisiteUnavailable) as caught:
            run()
        self.assertEqual(caught.exception.missing_tools, ["dpkg-query"])

    def test_foreign_architecture_elf_anywhere_in_the_payload_is_rejected(self):
        foreign = build_elf(machine="aarch64", elf_type="shared", needed=["libc.so.6"], soname="libforeign.so")
        extra = [("theme-forge-nebular-fusion/lib/libforeign.so", foreign, 0o755, tarfile.REGTYPE, "")]
        _, run = self.build(self.runner(), extra_linux=extra)
        with self.assertRaises(ContractError) as caught:
            run()
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")
        self.assertEqual(self.calls["shlibdeps"], [])

    def test_unparseable_or_empty_derived_dependencies_never_qualify(self):
        elf = [{"path": "bin/tool", "type": "executable"}]
        for output, code in ((b"shlibs:Depends=Bad_Name (>= 1)\n", "NATIVE_DEPENDENCY_DERIVATION_UNQUALIFIED"),
                             (b"", "NATIVE_DEPENDENCY_DERIVATION_UNQUALIFIED"),
                             (b"unrelated output\n", "NATIVE_DEPENDENCY_DERIVATION_UNQUALIFIED")):
            scratch = self.root / f"direct-{len(list(self.root.iterdir()))}"
            scratch.mkdir()
            pkg_root = scratch / "pkg"
            pkg_root.mkdir()
            runner = MockCommandRunner(available_tools={"dpkg-shlibdeps": "/x", "dpkg-query": "/y"},
                                       handlers={"dpkg-shlibdeps": {"stdout": output}})
            with self.subTest(output=output), self.assertRaises(ContractError) as caught:
                derive_native_dependencies(runner, scratch, pkg_root, "proj", "amd64", self.MAINTAINER, elf)
            self.assertEqual(caught.exception.code, code)

    def test_private_library_directories_are_passed_to_shlibdeps(self):
        scratch = self.root / "libdirs"
        scratch.mkdir()
        pkg_root = scratch / "pkg"
        pkg_root.mkdir()
        elf = [{"path": "usr/lib/p/bin/app", "type": "executable"}, {"path": "usr/lib/p/lib/libp.so", "type": "shared"}]
        runner = MockCommandRunner(
            available_tools={"dpkg-shlibdeps": "/x", "dpkg-query": "/y"},
            handlers={"dpkg-shlibdeps": {"stdout": b"shlibs:Depends=libc6 (>= 2.34)\n"},
                      "dpkg-query": {"stdout": b"libc6\t2.43-1\tamd64\n"}})
        receipt, depends, query, inventory = derive_native_dependencies(
            runner, scratch, pkg_root, "proj", "amd64", self.MAINTAINER, elf)
        argv = receipt.command
        self.assertIn(f"-l{pkg_root / 'usr/lib/p/lib'}", argv)
        self.assertEqual([a for a in argv if a.startswith("-e")],
                         [f"-e{pkg_root / 'usr/lib/p/bin/app'}", f"-e{pkg_root / 'usr/lib/p/lib/libp.so'}"])
        self.assertEqual(depends, "libc6 (>= 2.34)")
        self.assertEqual(inventory["packages"], [{"name": "libc6", "version": "2.43-1", "architecture": "amd64"}])
        self.assertEqual(inventory["query_stdout_sha256"], query.stdout_sha256)


class ElfInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_inventory_lists_every_regular_elf_in_sorted_order_with_strict_parsing(self):
        (self.root / "usr/lib/p/lib").mkdir(parents=True)
        (self.root / "usr/bin").mkdir(parents=True)
        exe = build_elf(machine="x86_64", needed=["libc.so.6"], interpreter="/lib64/ld-linux-x86-64.so.2")
        lib = build_elf(machine="x86_64", elf_type="shared", soname="libp.so", needed=["libm.so.6"], rpath=["$ORIGIN"])
        (self.root / "usr/lib/p/lib/libp.so").write_bytes(lib)
        (self.root / "usr/bin/tool").write_bytes(exe)
        (self.root / "usr/bin/script").write_bytes(b"#!/bin/sh\n")
        (self.root / "usr/bin/data").write_bytes(b"\x00\x01binary but not elf")
        try:
            os.symlink("tool", self.root / "usr/bin/alias")
        except OSError:
            pass
        rows = collect_elf_inventory(self.root)
        self.assertEqual([row["path"] for row in rows], ["usr/bin/tool", "usr/lib/p/lib/libp.so"])
        self.assertEqual(rows[0]["needed"], ["libc.so.6"])
        self.assertEqual(rows[0]["interpreter"], "/lib64/ld-linux-x86-64.so.2")
        self.assertEqual((rows[1]["type"], rows[1]["rpath"], rows[1]["machine"]), ("shared", ["$ORIGIN"], "x86_64"))
        self.assertEqual(rows[0]["sha256"], digest(exe))
        # Paths are relative to the inspected root.
        self.assertEqual(collect_elf_inventory(self.root / "usr/lib"), [{**rows[1], "path": "p/lib/libp.so"}])

    def test_unsupported_elf_fails_closed_rather_than_being_skipped(self):
        (self.root / "bin").mkdir()
        (self.root / "bin/elf32").write_bytes(build_elf(ei_class=1))
        with self.assertRaises(ContractError) as caught:
            collect_elf_inventory(self.root)
        self.assertEqual(caught.exception.code, "UNSUPPORTED_ELF")

    def test_machine_mapping_matches_deb_architectures(self):
        self.assertEqual(ELF_MACHINE, {"amd64": "x86_64", "arm64": "aarch64"})


class BurstDebCandidateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()

    def _make_burst_fixture(self):
        from rs9.burst_native import BURST_CLOSED_PREBUILDS
        from tests.test_burst_platform_wheel import make_synthetic_elf, make_synthetic_macho

        prebuild_binaries = {
            "darwin-arm64": make_synthetic_macho("arm64", 13, 0),
            "darwin-x64": make_synthetic_macho("x86_64", 15, 0),
            "linux-arm64-gnu": make_synthetic_elf("aarch64"),
            "linux-x64-gnu": make_synthetic_elf("x86_64"),
        }
        extra_entries = [
            (path.removeprefix("package/"), prebuild_binaries[key])
            for key, path in BURST_CLOSED_PREBUILDS.items()
        ]
        burst_input = self.root / "burst_input"
        capture, intent, offline_npm = create_cli_fixture(
            burst_input,
            product="theme-forge-stellar-burst",
            extra_asset_entries=extra_entries,
        )
        return capture, intent, offline_npm

    def test_burst_deb_rejects_architecture_all(self):
        capture, intent, offline_npm = self._make_burst_fixture()
        runner = MockCommandRunner(
            available_tools={"dpkg-deb": "/usr/bin/dpkg-deb", "dpkg-shlibdeps": "/usr/bin/dpkg-shlibdeps", "dpkg-query": "/usr/bin/dpkg-query"}
        )
        with self.assertRaises(ContractError) as caught:
            build_deb_candidate(
                capture, intent, "all", self.scratch,
                maintainer="Team <team@example.com>",
                offline_npm_archives=offline_npm,
                runner=runner,
            )
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_burst_deb_builds_amd64_isolating_matching_prebuild(self):
        capture, intent, offline_npm = self._make_burst_fixture()
        calls = {"deb": [], "shlibdeps": [], "query": []}

        def deb_handler(argv, cwd=None, env=None):
            calls["deb"].append(argv)
            Path(argv[-1]).write_bytes(make_minimal_deb(
                "theme-forge-stellar-burst", "0.6.1", 1, "amd64", "Team <team@example.com>", "Burst", "nodejs (>= 22), libc6"
            ))
            return CommandReceipt(argv, 0, b"", b"")

        def shlibdeps_handler(argv, cwd=None, env=None):
            calls["shlibdeps"].append(argv)
            exe_args = [a for a in argv if a.startswith("-e")]
            assert len(exe_args) == 1, f"Expected 1 matching prebuild ELF, got {exe_args}"
            assert "linux-x64-gnu" in exe_args[0], f"Expected linux-x64-gnu in {exe_args[0]}"
            return CommandReceipt(argv, 0, b"shlibs:Depends=libc6 (>= 2.34)\n", b"")

        def query_handler(argv, cwd=None, env=None):
            calls["query"].append(argv)
            return CommandReceipt(argv, 0, b"libc6\t2.35-0ubuntu3\tamd64\n", b"")

        runner = MockCommandRunner(
            available_tools={
                "dpkg-deb": "/usr/bin/dpkg-deb",
                "dpkg-shlibdeps": "/usr/bin/dpkg-shlibdeps",
                "dpkg-query": "/usr/bin/dpkg-query",
            },
            handlers={
                "dpkg-deb": deb_handler,
                "dpkg-shlibdeps": shlibdeps_handler,
                "dpkg-query": query_handler,
            },
        )
        result = build_deb_candidate(
            capture, intent, "amd64", self.scratch,
            maintainer="Team <team@example.com>",
            offline_npm_archives=offline_npm,
            runner=runner,
        )
        self.assertEqual(result["manifest"]["architecture"], "amd64")
        self.assertEqual(result["manifest"]["dependency_classification"], "native-tool-derived")
        self.assertIn("nodejs (>= 22)", result["manifest"]["dependencies"])
        self.assertIn("libc6 (>= 2.34)", result["manifest"]["dependencies"])
        self.assertEqual(result["manifest"]["elf_object_count"], 1)

    def test_reserved_maintainer_syntax_validation(self):
        from rs9.build_native import validate_maintainer
        # Valid reserved maintainer
        valid = "Knowledge Forge AI <nonproduction@knowledge-forge.invalid>"
        self.assertEqual(validate_maintainer(valid), valid)

        # Invalid domain without dot fails
        with self.assertRaises(ContractError) as caught:
            validate_maintainer("Knowledge Forge AI <nonproduction@invalid>")
        self.assertEqual(caught.exception.code, "INVALID_METADATA")

        # Verify targets.json maintainer is valid per validate_maintainer
        targets_path = Path(__file__).resolve().parents[1] / "operators/live1/targets.json"
        targets = json.loads(targets_path.read_bytes())
        self.assertEqual(validate_maintainer(targets["maintainer"]), valid)

    def test_burst_deb_closure_retention_regression(self):
        capture, intent, offline_npm = self._make_burst_fixture()

        def deb_h(argv, cwd=None, env=None):
            Path(argv[-1]).write_bytes(make_minimal_deb(
                "theme-forge-stellar-burst", "0.6.1", 1, "amd64",
                "Knowledge Forge AI <nonproduction@knowledge-forge.invalid>", "Burst", "nodejs (>= 22)"
            ))
            return CommandReceipt(argv, 0, b"", b"")

        runner = MockCommandRunner(
            available_tools={"dpkg-deb": "/usr/bin/dpkg-deb", "dpkg-shlibdeps": "/usr/bin/dpkg-shlibdeps", "dpkg-query": "/usr/bin/dpkg-query"},
            handlers={
                "dpkg-deb": deb_h,
                "dpkg-shlibdeps": lambda argv, cwd=None, env=None: CommandReceipt(argv, 0, b"shlibs:Depends=libc6 (>= 2.34)\n", b""),
                "dpkg-query": lambda argv, cwd=None, env=None: CommandReceipt(argv, 0, b"libc6\t2.35-0ubuntu3\tamd64\n", b""),
            },
        )
        # Omission of offline_npm_archives for Burst fails closed
        fail_scratch = self.scratch / "fail_scratch"
        fail_scratch.mkdir()
        with self.assertRaises(ContractError) as caught:
            build_deb_candidate(
                capture, intent, "amd64", fail_scratch,
                maintainer="Knowledge Forge AI <nonproduction@knowledge-forge.invalid>",
                offline_npm_archives=None,
                runner=runner,
            )
        self.assertEqual(caught.exception.code, "NPM_CLOSURE")

        # Supplying offline_npm stages the node_modules closure
        burst_scratch = self.scratch / "burst_closure_scratch"
        burst_scratch.mkdir()
        result = build_deb_candidate(
            capture, intent, "amd64", burst_scratch,
            maintainer="Knowledge Forge AI <nonproduction@knowledge-forge.invalid>",
            offline_npm_archives=offline_npm,
            runner=runner,
        )
        pkg_root = burst_scratch / "pkg/theme-forge-stellar-burst_0.6.1-1_amd64"
        staged_dep = pkg_root / "usr/lib/theme-forge-stellar-burst/node_modules/min-dep"
        self.assertTrue(staged_dep.is_dir())
        self.assertTrue((staged_dep / "package.json").is_file())


if __name__ == "__main__":
    unittest.main()
