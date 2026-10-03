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
    build_deb_candidate,
    main as deb_main,
)
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

    # control.tar.gz
    ctrl_buf = io.BytesIO()
    with tarfile.open(fileobj=ctrl_buf, mode="w:gz") as tar:
        ti = tarfile.TarInfo("./control")
        ti.size = len(control_content)
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(control_content))
    ctrl_data = ctrl_buf.getvalue()

    # data.tar.gz
    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w:gz") as tar:
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
        + ar_entry("control.tar.gz", ctrl_data)
        + ar_entry("data.tar.gz", data_bytes)
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
            out_deb = Path(argv[4])
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


if __name__ == "__main__":
    unittest.main()
