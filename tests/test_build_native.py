"""Tests for common native package candidate builder, pacman, and RPM drivers."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from rs9.build_native import (
    CommandReceipt,
    MockCommandRunner,
    NATIVE_LIBRARY_SUFFIXES,
    NATIVE_MAGIC_PREFIXES,
    NativePrerequisiteUnavailable,
    SubprocessRunner,
    assert_no_native_payloads,
    build_native_main,
    check_prerequisites,
    is_native_payload,
    stage_offline_npm_closure,
    validate_build_inputs,
    validate_scratch_root,
    verify_nebular_sidecar,
)
from rs9.build_pacman import PACMAN_REQUIRED_TOOLS, build_pacman_candidate
from rs9.build_rpm import RPM_REQUIRED_TOOLS, build_rpm_candidate
from rs9.errors import ContractError
from rs9.profiles import selection_for_intent
from rs9.release_core import authenticate_release, digest
from rs9.scratch import canonical
from tests.publication_fixtures import authorize_fixture_configuration
from tests.shadow_fixtures import fixture_evidence, tar_bytes


def make_npm_archive(
    dest_dir: Path,
    name: str,
    version: str,
    license_type: str = "MIT",
    extra_entries: list[tuple[str, bytes]] | None = None,
    pkg_json_override: dict | None = None,
) -> tuple[Path, str]:
    """Create a minimal authenticated npm dependency tarball."""
    pkg_json = canonical(
        pkg_json_override
        if pkg_json_override is not None
        else {
            "name": name,
            "version": version,
            "license": license_type,
        }
    )
    entries = [
        ("package/package.json", pkg_json, 0o644, tarfile.REGTYPE, ""),
        ("package/LICENSE", b"MIT License\n", 0o644, tarfile.REGTYPE, ""),
    ]
    if extra_entries:
        for rel_path, data in extra_entries:
            entries.append((f"package/{rel_path}", data, 0o755 if "bin" in rel_path else 0o644, tarfile.REGTYPE, ""))
    data = tar_bytes(entries)
    archive_path = dest_dir / f"{name}-{version}.tgz"
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    archive_path.write_bytes(data)
    import base64
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
    return archive_path, integrity


def create_cli_fixture(
    root: Path,
    product: str = "theme-forge-stellar-loom",
    *,
    extra_asset_entries: list[tuple[str, bytes]] | None = None,
    extra_dep_entries: list[tuple[str, bytes]] | None = None,
    dep_pkg_json_override: dict | None = None,
) -> tuple[Any, dict, dict]:
    """Create synthetic CLI project capture with package-lock for npm closure."""
    root.mkdir(parents=True, exist_ok=True)
    version = "0.4.0" if product.endswith("loom") else ("0.6.1" if product.endswith("burst") else "0.2.1")
    tag = "v" + version
    repo = "Knowledge-Forge-AI/" + product
    commands = (
        {"tfsl": "bin/run.js", "tfsl-batch": "bin/batch.js"}
        if product.endswith("loom")
        else ({"tfsb": "bin/run.js", "tfsb-studio-service": "bin/srv.js"} if product.endswith("burst") else {"tfss": "bin/run.js"})
    )

    dep_archive_dir = root / "npm_archives"
    dep_archive_dir.mkdir(parents=True, exist_ok=True)
    archive_file, integrity = make_npm_archive(
        dep_archive_dir, "min-dep", "1.0.0", extra_entries=extra_dep_entries, pkg_json_override=dep_pkg_json_override
    )

    pkg_source = {
        "name": "@knowledge-forge-ai/" + product,
        "version": version,
        "license": "AGPL-3.0-or-later",
        "bin": commands,
        "dependencies": {"min-dep": "1.0.0"},
    }
    lock_source = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"min-dep": "1.0.0"}},
            "node_modules/min-dep": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/min-dep/-/min-dep-1.0.0.tgz",
                "integrity": integrity,
            },
        },
    }

    raw_pkg = canonical(pkg_source)
    raw_lock = canonical(lock_source)

    (root / "source").mkdir(parents=True, exist_ok=True)
    (root / "source/package.json").write_bytes(raw_pkg)
    (root / "source/package-lock.json").write_bytes(raw_lock)

    tree_entries = [
        {"path": "package.json", "sha": hashlib.sha1(b"blob " + str(len(raw_pkg)).encode() + b"\0" + raw_pkg).hexdigest(), "type": "blob", "mode": "100644"},
        {"path": "package-lock.json", "sha": hashlib.sha1(b"blob " + str(len(raw_lock)).encode() + b"\0" + raw_lock).hexdigest(), "type": "blob", "mode": "100644"},
    ]
    (root / "api").mkdir(parents=True, exist_ok=True)
    (root / "api/tree.json").write_bytes(canonical({"sha": "b" * 40, "truncated": False, "tree": tree_entries}))

    asset_name = f"{product}-{version}.tgz"
    asset_entries = [
        ("package/package.json", raw_pkg, 0o644, tarfile.REGTYPE, ""),
        ("package/package-lock.json", raw_lock, 0o644, tarfile.REGTYPE, ""),
        *[("package/" + path, b"#!/usr/bin/env node\n", 0o755, tarfile.REGTYPE, "") for path in commands.values()],
    ]
    if extra_asset_entries:
        for rel_path, data in extra_asset_entries:
            asset_entries.append((f"package/{rel_path}", data, 0o755 if "bin" in rel_path else 0o644, tarfile.REGTYPE, ""))
    asset_tar = tar_bytes(asset_entries)

    (root / "assets").mkdir(parents=True, exist_ok=True)
    (root / "assets" / asset_name).write_bytes(asset_tar)
    (root / "assets/PROVENANCE.json").write_bytes(canonical({"release": {"repository": repo, "tag": tag, "tagTarget": "a" * 40, "mergedMainTree": "b" * 40}}))
    (root / "assets/NOTICE").write_bytes(b"Theme Forge Notice\n")

    staged = {p.name: p.read_bytes() for p in (root / "assets").iterdir() if p.name != "SHA256SUMS"}
    (root / "assets/SHA256SUMS").write_bytes("".join(digest(b) + "  " + name + "\n" for name, b in sorted(staged.items())).encode())

    (root / "api/tags.json").write_bytes(canonical([]))
    (root / "api/repository.json").write_bytes(canonical({"id": 99, "full_name": repo}))
    (root / "api/ref.json").write_bytes(canonical({"ref": "refs/tags/" + tag, "object": {"type": "commit", "sha": "a" * 40}}))
    (root / "api/commit.json").write_bytes(canonical({"sha": "a" * 40, "tree": {"sha": "b" * 40}}))

    all_files = {p.name: p.read_bytes() for p in (root / "assets").iterdir()}
    rel_assets = [
        {"id": i + 1, "name": name, "size": len(b), "digest": "sha256:" + digest(b), "state": "uploaded"}
        for i, (name, b) in enumerate(sorted(all_files.items()))
    ]
    (root / "api/release.json").write_bytes(canonical({"id": 101, "tag_name": tag, "target_commitish": "a" * 40, "draft": False, "prerelease": False, "assets": rel_assets}))

    intent = {
        "project": {"repository": repo, "id": product, "summary": "Synthetic CLI project candidate"},
        "version": version,
        "tag": tag,
        "license": {"expression": "AGPL-3.0-or-later", "files": ["package-lock.json"]},
        "release": {
            "prerelease": "reject",
            "evidence": {
                "profile": "npm-package-archive.v1alpha1",
                "checksums": "SHA256SUMS",
                "assets": [
                    {"role": "notice", "name": "NOTICE"},
                    {"role": "provenance", "name": "PROVENANCE.json"},
                ],
            },
        },
        "assets": [{"id": "package", "name": asset_name, "format": "tar.gz", "commands": {k: "package/" + v for k, v in commands.items()}, "platforms": ["any"]}],
    }

    capture = authenticate_release(selection_for_intent(intent), root)
    authorize_fixture_configuration(root, intent, capture)
    offline_npm = {"node_modules/min-dep": str(archive_file)}
    return capture, intent, offline_npm


class BuildNativeCommonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_scratch_validation_rejects_non_empty_and_symlinks(self):
        scratch = self.root / "scratch"
        scratch.mkdir()
        # Empty succeeds
        self.assertEqual(validate_scratch_root(scratch), scratch)

        # Non-empty fails with OUTPUT_NOT_EMPTY
        (scratch / "dirty.txt").write_bytes(b"data")
        with self.assertRaises(ContractError) as caught:
            validate_scratch_root(scratch)
        self.assertEqual(caught.exception.code, "OUTPUT_NOT_EMPTY")

        # Symlink ancestry fails
        link_dir = self.root / "scratch_link"
        link_dir.symlink_to(scratch)
        with self.assertRaises(ContractError) as caught_link:
            validate_scratch_root(link_dir)
        self.assertEqual(caught_link.exception.code, "SYMLINK_REJECTED")

    @patch("rs9.build_native.shutil.which", return_value=None)
    def test_prerequisites_absent_explicit_unavailable_never_fabricated(self, _which):
        # Native host environment without pacman / rpm tools
        pacman_status = check_prerequisites("pacman", PACMAN_REQUIRED_TOOLS)
        rpm_status = check_prerequisites("rpm", RPM_REQUIRED_TOOLS)

        # The explicit missing-tool seam is independent of the test host
        self.assertFalse(pacman_status["available"])
        self.assertIn("makepkg", pacman_status["missing"])
        self.assertFalse(rpm_status["available"])
        self.assertIn("rpmbuild", rpm_status["missing"])

        # Running builders with missing tools raises NativePrerequisiteUnavailable
        capture, intent, _ = create_cli_fixture(self.root / "loom_input")
        scratch_pacman = self.root / "scratch_pacman"
        scratch_pacman.mkdir()
        scratch_rpm = self.root / "scratch_rpm"
        scratch_rpm.mkdir()

        with self.assertRaises(NativePrerequisiteUnavailable) as caught_pac:
            build_pacman_candidate(capture, intent, "any", scratch_pacman)
        self.assertEqual(caught_pac.exception.code, "TOOL_UNAVAILABLE")
        # Ensure no fabricated files exist
        self.assertEqual(list(scratch_pacman.iterdir()), [])

        with self.assertRaises(NativePrerequisiteUnavailable) as caught_rpm:
            build_rpm_candidate(capture, intent, "noarch", scratch_rpm)
        self.assertEqual(caught_rpm.exception.code, "TOOL_UNAVAILABLE")
        self.assertEqual(list(scratch_rpm.iterdir()), [])

    def test_cli_architecture_truthfulness_enforces_any_and_noarch(self):
        capture, intent, _ = create_cli_fixture(self.root / "loom_input")
        scratch = self.root / "scratch"
        scratch.mkdir()

        runner = MockCommandRunner(
            available_tools={"makepkg": "/usr/bin/makepkg", "repo-add": "/usr/bin/repo-add",
                             "rpmbuild": "/usr/bin/rpmbuild", "rpm": "/usr/bin/rpm",
                             "rpmlint": "/usr/bin/rpmlint", "createrepo_c": "/usr/bin/createrepo_c"}
        )

        # CLI pacman must be 'any', rejects x86_64
        with self.assertRaises(ContractError) as caught_pac:
            build_pacman_candidate(capture, intent, "x86_64", scratch, runner=runner)
        self.assertEqual(caught_pac.exception.code, "INVALID_ARCHITECTURE")

        # CLI RPM must be 'noarch', rejects x86_64
        with self.assertRaises(ContractError) as caught_rpm:
            build_rpm_candidate(capture, intent, "x86_64", scratch, runner=runner)
        self.assertEqual(caught_rpm.exception.code, "INVALID_ARCHITECTURE")

    def test_native_architecture_truthfulness_enforces_platform_archs(self):
        neb_dir = self.root / "nebular"
        neb_dir.mkdir()
        intent = fixture_evidence(neb_dir)
        capture = authenticate_release(selection_for_intent(intent), neb_dir)
        authorize_fixture_configuration(neb_dir, intent, capture)

        scratch = self.root / "scratch"
        scratch.mkdir()

        runner = MockCommandRunner(
            available_tools={"makepkg": "/usr/bin/makepkg", "repo-add": "/usr/bin/repo-add",
                             "rpmbuild": "/usr/bin/rpmbuild", "rpm": "/usr/bin/rpm",
                             "rpmlint": "/usr/bin/rpmlint", "createrepo_c": "/usr/bin/createrepo_c"}
        )

        # Nebular pacman must be x86_64, rejects 'any' and 'aarch64'
        with self.assertRaises(ContractError) as caught_pac:
            build_pacman_candidate(capture, intent, "any", scratch, runner=runner)
        self.assertEqual(caught_pac.exception.code, "INVALID_ARCHITECTURE")

        # Nebular RPM rejects 'noarch'
        with self.assertRaises(ContractError) as caught_rpm:
            build_rpm_candidate(capture, intent, "noarch", scratch, runner=runner)
        self.assertEqual(caught_rpm.exception.code, "INVALID_ARCHITECTURE")

    def test_cli_offline_npm_closure_fail_closed(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input")
        scratch1 = self.root / "scratch_m1"
        scratch1.mkdir()
        scratch2 = self.root / "scratch_m2"
        scratch2.mkdir()
        scratch3 = self.root / "scratch_m3"
        scratch3.mkdir()

        runner = MockCommandRunner(
            available_tools={"makepkg": "/usr/bin/makepkg", "repo-add": "/usr/bin/repo-add"}
        )

        # Missing offline npm closure fails closed
        with self.assertRaises(ContractError) as caught_missing:
            build_pacman_candidate(capture, intent, "any", scratch1, offline_npm_archives=None, runner=runner)
        self.assertEqual(caught_missing.exception.code, "NPM_CLOSURE")

        # Empty offline npm closure fails closed
        with self.assertRaises(ContractError) as caught_empty:
            build_pacman_candidate(capture, intent, "any", scratch2, offline_npm_archives={}, runner=runner)
        self.assertEqual(caught_empty.exception.code, "NPM_CLOSURE")

        # Tampered offline npm archive fails closed
        tampered_archive = self.root / "tampered.tgz"
        tampered_archive.write_bytes(b"tampered content")
        with self.assertRaises(ContractError) as caught_tamper:
            build_pacman_candidate(
                capture, intent, "any", scratch3,
                offline_npm_archives={"node_modules/min-dep": str(tampered_archive)},
                runner=runner
            )
        self.assertEqual(caught_tamper.exception.code, "NPM_INTEGRITY")

    def test_burst_supported_closure_requires_a_real_package(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "burst_input", product="theme-forge-stellar-burst")
        scratch = self.root / "scratch_burst"
        scratch.mkdir()

        runner = MockCommandRunner(
            available_tools={"makepkg": "/usr/bin/makepkg", "repo-add": "/usr/bin/repo-add"}
        )
        with self.assertRaises(ContractError) as caught:
            build_pacman_candidate(capture, intent, "any", scratch, offline_npm_archives=offline_npm, runner=runner)
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_burst_rpm_plan_f2_and_architecture_validation(self):
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
        capture, intent, offline_npm = create_cli_fixture(
            self.root / "burst_rpm_input",
            product="theme-forge-stellar-burst",
            extra_asset_entries=extra_entries,
        )
        scratch = self.root / "scratch_burst_rpm"
        scratch.mkdir()

        runner = MockCommandRunner(
            available_tools={"rpmbuild": "/usr/bin/rpmbuild", "rpm": "/usr/bin/rpm", "createrepo_c": "/usr/bin/createrepo_c"}
        )
        with self.assertRaises(ContractError) as caught:
            build_rpm_candidate(capture, intent, "noarch", scratch, offline_npm_archives=offline_npm, runner=runner)
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

        spec_captured = []
        def rpmbuild_handler(argv, cwd=None, env=None):
            spec_file = Path(argv[2])
            spec_captured.append(spec_file.read_text("utf-8"))
            rpm_dir = Path(cwd) / "RPMS/x86_64"
            rpm_dir.mkdir(parents=True, exist_ok=True)
            (rpm_dir / "theme-forge-stellar-burst-0.6.1-1.fc42.x86_64.rpm").write_bytes(b"synthetic-burst-rpm")
            return CommandReceipt(argv, 0, b"rpmbuild ok\n", b"")

        def rpm_handler(argv, cwd=None, env=None):
            if "--requires" in argv:
                return CommandReceipt(argv, 0, b"nodejs >= 22\n", b"")
            return CommandReceipt(argv, 0, b"theme-forge-stellar-burst|0.6.1|1.fc43|x86_64|abcdef0123456789|sha256\n", b"")

        def createrepo_handler(argv, cwd=None, env=None):
            repodata = Path(argv[-1]) / "repodata"
            repodata.mkdir(parents=True, exist_ok=True)
            (repodata / "repomd.xml").write_bytes(b"<repomd/>")
            return CommandReceipt(argv, 0, b"createrepo ok\n", b"")

        def rpmlint_handler(argv, cwd=None, env=None):
            return CommandReceipt(argv, 0, b"0 packages and 0 specfiles checked; 0 errors, 0 warnings.\n", b"")

        runner = MockCommandRunner(
            available_tools={
                "rpmbuild": "/usr/bin/rpmbuild",
                "rpm": "/usr/bin/rpm",
                "rpmlint": "/usr/bin/rpmlint",
                "createrepo_c": "/usr/bin/createrepo_c",
            },
            handlers={
                "rpmbuild": rpmbuild_handler,
                "rpm": rpm_handler,
                "rpmlint": rpmlint_handler,
                "createrepo_c": createrepo_handler,
            },
        )
        result = build_rpm_candidate(
            capture, intent, "x86_64", scratch,
            offline_npm_archives=offline_npm,
            runner=runner,
        )
        self.assertEqual(result["manifest"]["architecture"], "x86_64")
        self.assertEqual(result["derivation_record"]["dependency_classification"], "native-tool-derived")
        self.assertTrue(spec_captured)
        spec_text = spec_captured[0]
        import re
        for directive in ("__requires_exclude_from", "__provides_exclude_from"):
            pattern = next(line.split(" ", 2)[2] for line in spec_text.splitlines() if line.startswith("%global " + directive + " "))
            for key, path in BURST_CLOSED_PREBUILDS.items():
                installed = "/usr/lib/theme-forge-stellar-burst/" + path.removeprefix("package/")
                self.assertEqual(bool(re.fullmatch(pattern, installed)), key != "linux-x64-gnu")
            self.assertIsNone(re.fullmatch(pattern, "/usr/lib/theme-forge-stellar-burst/native/unexpected.node"))
            self.assertNotIn("(?:", pattern)
        self.assertIn("ExclusiveArch: x86_64", spec_text)

    def test_pacman_builder_seam_and_derivation_record(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input")
        scratch = self.root / "scratch_pacman"
        scratch.mkdir()

        def makepkg_handler(argv, cwd=None, env=None):
            # Verify truthful extraction path: makepkg --noextract requires pre-populated $srcdir
            src_dir = Path(cwd) / "src"
            assert (src_dir / "package").is_dir(), "$srcdir/package must be extracted before makepkg"
            assert (src_dir / "package/package.json").is_file(), "$srcdir/package/package.json must exist"
            assert (src_dir / "node_modules").is_dir(), "$srcdir/node_modules must be staged before makepkg"
            assert (src_dir / "node_modules/min-dep").is_dir(), "$srcdir/node_modules/min-dep must exist"

            # Simulate makepkg producing a package file in cwd
            pkg_name = f"theme-forge-stellar-loom-0.4.0-1-any.pkg.tar.zst"
            pkg_path = Path(cwd) / pkg_name
            pkg_path.write_bytes(b"synthetic-pacman-package-bytes")
            return CommandReceipt(argv, 0, b"makepkg success\n", b"")

        def repo_add_handler(argv, cwd=None, env=None):
            # argv: repo-add <repo_db> <pkg_file>
            db_path = Path(argv[1])
            db_path.parent.mkdir(parents=True, exist_ok=True)
            db_path.write_bytes(b"synthetic-repo-db-tar-gz")
            return CommandReceipt(argv, 0, b"repo-add success\n", b"")

        runner = MockCommandRunner(
            available_tools={"makepkg": "/usr/bin/makepkg", "repo-add": "/usr/bin/repo-add"},
            handlers={"makepkg": makepkg_handler, "repo-add": repo_add_handler},
        )

        result = build_pacman_candidate(
            capture, intent, "any", scratch,
            offline_npm_archives=offline_npm,
            runner=runner,
        )

        manifest = result["manifest"]
        derivation = result["derivation_record"]

        self.assertEqual(manifest["status"], "unsigned-candidate")
        self.assertEqual(manifest["qualification"], "unqualified-candidate")
        self.assertFalse(manifest["can_publish"])
        self.assertEqual(manifest["architecture"], "any")
        self.assertEqual(manifest["dependencies"], ["nodejs>=22"])
        self.assertEqual(manifest["dependency_classification"], "reviewed-policy")

        self.assertEqual(derivation["schema"], "rs9.native-derivation.v1alpha1")
        self.assertEqual(derivation["tool"]["tool"], "makepkg")
        self.assertEqual(len(derivation["tool_receipts"]), 2)
        self.assertEqual(derivation["tool_receipts"][1]["tool"], "repo-add")
        self.assertFalse(derivation["can_publish"])
        self.assertEqual(derivation["dependency_classification"], "reviewed-policy")
        self.assertEqual(derivation["derivation_source"], "reviewed-policy")
        self.assertEqual(derivation["builder_execution_source"], "synthetic-command-seam")

        # Verify truthful extraction path on disk
        extracted_src = scratch / "pacman/theme-forge-stellar-loom/src"
        self.assertTrue((extracted_src / "package").is_dir())
        self.assertTrue((extracted_src / "package/package.json").is_file())
        self.assertTrue((extracted_src / "node_modules").is_dir())
        self.assertTrue((extracted_src / "node_modules/min-dep").is_dir())

    def test_rpm_builder_preserves_flags_identities_and_rpmlint(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "loom_input")
        scratch = self.root / "scratch_rpm"
        scratch.mkdir()

        spec_seen = []

        def rpmbuild_handler(argv, cwd=None, env=None):
            # Verify preserve flags were passed
            self.assertIn("--define", argv)
            self.assertIn("debug_package %{nil}", argv)
            self.assertIn("__strip /bin/true", argv)
            self.assertIn("_build_id_links none", argv)
            self.assertIn("__os_install_post %{nil}", argv)
            self.assertIn("--undefine", argv)
            self.assertIn("__brp_mangle_shebangs", argv)

            # Check spec file content
            spec_file = Path(argv[2])
            spec_content = spec_file.read_text("utf-8")
            spec_seen.append(spec_content)
            self.assertIn("BuildArch: noarch", spec_content)
            self.assertIn("%global debug_package %{nil}", spec_content)
            self.assertIn("%global __strip /bin/true", spec_content)
            self.assertIn("%undefine __brp_mangle_shebangs", spec_content)
            self.assertIn("%global _build_id_links none", spec_content)
            self.assertIn("%global __os_install_post %{nil}", spec_content)

            # Generate built RPM in RPMS/noarch
            rpm_dir = Path(cwd) / "RPMS" / "noarch"
            rpm_dir.mkdir(parents=True, exist_ok=True)
            (rpm_dir / "theme-forge-stellar-loom-0.4.0-1.fc43.noarch.rpm").write_bytes(b"synthetic-rpm-bytes")
            return CommandReceipt(argv, 0, b"rpmbuild success\n", b"")

        def rpm_query_handler(argv, cwd=None, env=None):
            out = "theme-forge-stellar-loom|0.4.0|1.fc43|noarch|abcdef0123456789|sha256\n".encode()
            return CommandReceipt(argv, 0, out, b"")

        def rpmlint_handler(argv, cwd=None, env=None):
            return CommandReceipt(argv, 0, b"0 packages and 1 specfiles checked; 0 errors, 0 warnings.\n", b"")

        def createrepo_handler(argv, cwd=None, env=None):
            self.assertIn("--no-database", argv)
            self.assertIn("-s", argv)
            self.assertIn("sha256", argv)
            repodata = Path(argv[-1]) / "repodata"
            repodata.mkdir(parents=True, exist_ok=True)
            (repodata / "repomd.xml").write_bytes(b"<repomd/>")
            (repodata / "primary.xml.gz").write_bytes(b"gzip-xml")
            return CommandReceipt(argv, 0, b"createrepo_c complete\n", b"")

        runner = MockCommandRunner(
            available_tools={
                "rpmbuild": "/usr/bin/rpmbuild",
                "rpm": "/usr/bin/rpm",
                "rpmlint": "/usr/bin/rpmlint",
                "createrepo_c": "/usr/bin/createrepo_c",
            },
            handlers={
                "rpmbuild": rpmbuild_handler,
                "rpm": rpm_query_handler,
                "rpmlint": rpmlint_handler,
                "createrepo_c": createrepo_handler,
            },
        )

        result = build_rpm_candidate(
            capture, intent, "noarch", scratch,
            offline_npm_archives=offline_npm,
            runner=runner,
        )

        manifest = result["manifest"]
        derivation = result["derivation_record"]

        self.assertEqual(manifest["architecture"], "noarch")
        self.assertEqual(manifest["rpm_v6_identity"]["payload_digest_algo"], "sha256")
        self.assertEqual(manifest["rpm_v6_identity"]["payload_digest"], "abcdef0123456789")
        self.assertEqual(len(derivation["tool_receipts"]), 4)
        self.assertFalse(derivation["can_publish"])
        self.assertEqual(derivation["dependency_classification"], "reviewed-policy")
        self.assertEqual(derivation["evidence"]["native_preservation"]["strip"], False)
        self.assertEqual(derivation["evidence"]["native_preservation"]["debug"], False)

    def test_nebular_sidecar_verifier_and_scenario_a(self):
        install_root = self.root / "neb_installed"
        (install_root / "usr/lib/theme-forge-nebular-fusion").mkdir(parents=True)
        (install_root / "usr/bin").mkdir(parents=True)
        (install_root / "usr/share/applications").mkdir(parents=True)
        (install_root / "usr/share/icons/hicolor/256x256/apps").mkdir(parents=True)

        binary = install_root / "usr/lib/theme-forge-nebular-fusion/tfnf"
        binary.write_bytes(b"ELF-bin")
        binary.chmod(0o755)

        launcher = install_root / "usr/bin/tfnf"
        launcher.symlink_to("/usr/lib/theme-forge-nebular-fusion/tfnf")

        (install_root / "usr/share/applications/theme-forge-nebular-fusion.desktop").write_bytes(b"[Desktop Entry]\n")
        (install_root / "usr/share/icons/hicolor/256x256/apps/theme-forge-nebular-fusion.png").write_bytes(b"\x89PNG\r\n\x1a\n")

        # Normal verification
        status = verify_nebular_sidecar(install_root)
        self.assertEqual(status["status"], "not-run")
        self.assertTrue(status["checks"]["binary_present"])
        self.assertTrue(status["checks"]["launcher_present"])

        # With Scenario-A
        runner = MockCommandRunner(
            available_tools={"/usr/bin/tfnf": "/usr/bin/tfnf"},
            handlers={"/usr/bin/tfnf": CommandReceipt(["/usr/bin/tfnf", "--version"], 0, b"tfnf 0.6.1\n", b"")},
        )
        scenario_a = {"command": ["/usr/bin/tfnf", "--version"], "expected_exit_code": 0}
        status_scen = verify_nebular_sidecar(install_root, scenario_a=scenario_a, runner=runner)
        self.assertEqual(status_scen["status"], "not-run")
        self.assertEqual(status_scen["scenario_a"]["status"], "not-run")
        self.assertFalse(runner.calls)

    @patch("rs9.build_native.shutil.which", return_value=None)
    def test_cli_command_driver_api(self, _which):
        # Missing prerequisites return failure on every test host
        code_pac = build_native_main(["--adapter", "pacman", "--arch", "any", "--check-prerequisites"])
        self.assertEqual(code_pac, 1)
        code_rpm = build_native_main(["--adapter", "rpm", "--arch", "noarch", "--check-prerequisites"])
        self.assertEqual(code_rpm, 1)

    def test_is_native_payload_detection_all_types(self):
        # ELF
        self.assertTrue(is_native_payload("bin/helper", b"\x7fELF\x02\x01\x01\x00"))
        # Mach-O 32-bit LE and BE
        self.assertTrue(is_native_payload("bin/helper", b"\xce\xfa\xed\xfe\x00\x00"))
        self.assertTrue(is_native_payload("bin/helper", b"\xfe\xed\xfa\xce\x00\x00"))
        # Mach-O 64-bit LE and BE
        self.assertTrue(is_native_payload("bin/helper", b"\xcf\xfa\xed\xfe\x00\x00"))
        self.assertTrue(is_native_payload("bin/helper", b"\xfe\xed\xfa\xcf\x00\x00"))
        # Mach-O Fat Universal 32-bit LE and BE
        self.assertTrue(is_native_payload("bin/helper", b"\xbe\xba\xfe\xca\x00\x00"))
        self.assertTrue(is_native_payload("bin/helper", b"\xca\xfe\xba\xbe\x00\x00"))
        # Mach-O Fat Universal 64-bit LE and BE
        self.assertTrue(is_native_payload("bin/helper", b"\xbf\xba\xfe\xca\x00\x00"))
        self.assertTrue(is_native_payload("bin/helper", b"\xca\xfe\xba\xbf\x00\x00"))
        # PE / DOS executable
        self.assertTrue(is_native_payload("bin/helper.exe", b"MZ\x90\x00\x03\x00"))
        self.assertTrue(is_native_payload("bin/helper", b"MZ\x90\x00\x03\x00"))

        # Suffix detection
        for sfx in NATIVE_LIBRARY_SUFFIXES:
            self.assertTrue(is_native_payload(f"lib/libfoo{sfx}", b"some-code"))
        # Versioned shared libraries
        self.assertTrue(is_native_payload("lib/libfoo.so.1.2.3", b"some-code"))
        self.assertTrue(is_native_payload("lib/libbar.dylib.1", b"some-code"))

        # Non-native scripts and files
        self.assertFalse(is_native_payload("bin/run.js", b"#!/usr/bin/env node\nconsole.log(1);\n"))
        self.assertFalse(is_native_payload("package.json", b'{"name": "test"}'))
        self.assertFalse(is_native_payload("README.md", b"# Markdown documentation\n"))
        self.assertFalse(is_native_payload("bin/script.sh", b"#!/bin/sh\necho hello\n"))

    def test_assert_no_native_payloads_fails_closed(self):
        with self.assertRaises(ContractError) as caught_node:
            assert_no_native_payloads({"addon.node": b"\x00" * 16}, context="Test")
        self.assertEqual(caught_node.exception.code, "INVALID_ARCHITECTURE")

        with self.assertRaises(ContractError) as caught_macho:
            assert_no_native_payloads({"bin/app": b"\xca\xfe\xba\xbe" + b"\x00" * 16}, context="Test")
        self.assertEqual(caught_macho.exception.code, "INVALID_ARCHITECTURE")

        with self.assertRaises(ContractError) as caught_pe:
            assert_no_native_payloads({"bin/app.exe": b"MZ" + b"\x00" * 16}, context="Test")
        self.assertEqual(caught_pe.exception.code, "INVALID_ARCHITECTURE")

        # Clean payload does not raise
        assert_no_native_payloads({
            "package.json": b'{"name": "clean"}',
            "bin/run.js": b"#!/usr/bin/env node\n",
        }, context="CleanTest")

    def test_cli_payload_with_native_binary_rejected_in_validate_build_inputs(self):
        # Mach-O in CLI project asset
        capture_macho, intent_macho, _ = create_cli_fixture(
            self.root / "bad_asset_macho",
            extra_asset_entries=[("bin/macho_bin", b"\xcf\xfa\xed\xfe" + b"\x00" * 20)],
        )
        with self.assertRaises(ContractError) as caught_macho:
            validate_build_inputs(capture_macho, intent_macho, "any", adapter="pacman")
        self.assertEqual(caught_macho.exception.code, "INVALID_ARCHITECTURE")

        # Windows PE in CLI project asset
        capture_pe, intent_pe, _ = create_cli_fixture(
            self.root / "bad_asset_pe",
            extra_asset_entries=[("bin/win_helper.exe", b"MZ" + b"\x00" * 20)],
        )
        with self.assertRaises(ContractError) as caught_pe:
            validate_build_inputs(capture_pe, intent_pe, "any", adapter="pacman")
        self.assertEqual(caught_pe.exception.code, "INVALID_ARCHITECTURE")

        # Native .node addon in CLI project asset
        capture_node, intent_node, _ = create_cli_fixture(
            self.root / "bad_asset_node",
            extra_asset_entries=[("bindings/addon.node", b"\x00" * 32)],
        )
        with self.assertRaises(ContractError) as caught_node:
            validate_build_inputs(capture_node, intent_node, "noarch", adapter="rpm")
        self.assertEqual(caught_node.exception.code, "INVALID_ARCHITECTURE")

    def test_offline_npm_closure_with_native_binary_fails_closed(self):
        # Native .node in npm dependency
        capture_node, _, offline_npm_node = create_cli_fixture(
            self.root / "dep_node",
            extra_dep_entries=[("binding.node", b"\x00" * 16)],
        )
        target_dir = self.root / "staged_node_modules_node"
        with self.assertRaises(ContractError) as caught_node:
            stage_offline_npm_closure(capture_node, "theme-forge-stellar-loom", offline_npm_node, target_dir)
        self.assertEqual(caught_node.exception.code, "INVALID_ARCHITECTURE")

        # Mach-O Fat Universal binary in npm dependency
        capture_macho, _, offline_npm_macho = create_cli_fixture(
            self.root / "dep_macho",
            extra_dep_entries=[("bin/tool", b"\xca\xfe\xba\xbe" + b"\x00" * 20)],
        )
        target_dir_macho = self.root / "staged_node_modules_macho"
        with self.assertRaises(ContractError) as caught_macho:
            stage_offline_npm_closure(capture_macho, "theme-forge-stellar-loom", offline_npm_macho, target_dir_macho)
        self.assertEqual(caught_macho.exception.code, "INVALID_ARCHITECTURE")

        # Windows PE binary in npm dependency
        capture_pe, _, offline_npm_pe = create_cli_fixture(
            self.root / "dep_pe",
            extra_dep_entries=[("bin/tool.dll", b"MZ" + b"\x00" * 20)],
        )
        target_dir_pe = self.root / "staged_node_modules_pe"
        with self.assertRaises(ContractError) as caught_pe:
            stage_offline_npm_closure(capture_pe, "theme-forge-stellar-loom", offline_npm_pe, target_dir_pe)
        self.assertEqual(caught_pe.exception.code, "INVALID_ARCHITECTURE")

    def test_offline_npm_closure_with_platform_restricted_os_cpu(self):
        pkg_json_os = {
            "name": "min-dep",
            "version": "1.0.0",
            "license": "MIT",
            "os": ["linux"],
        }
        capture, _, offline_npm = create_cli_fixture(
            self.root / "dep_restricted",
            dep_pkg_json_override=pkg_json_os,
        )
        target_dir = self.root / "staged_node_modules_restricted"
        with self.assertRaises(ContractError) as caught:
            stage_offline_npm_closure(capture, "theme-forge-stellar-loom", offline_npm, target_dir)
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_pacman_builder_native_nebular_dt_needed(self):
        neb_dir = self.root / "neb_pacman"
        neb_dir.mkdir()
        intent = fixture_evidence(neb_dir)
        capture = authenticate_release(selection_for_intent(intent), neb_dir)
        authorize_fixture_configuration(neb_dir, intent, capture)

        scratch = self.root / "scratch_neb_pacman"
        scratch.mkdir()

        def makepkg_handler(argv, cwd=None, env=None):
            src_dir = Path(cwd) / "src"
            assert (src_dir / "theme-forge-nebular-fusion").is_dir(), "$srcdir/theme-forge-nebular-fusion must exist"
            assert (src_dir / "theme-forge-nebular-fusion.desktop").is_file(), "desktop file must exist in $srcdir"
            assert (src_dir / "icon.png").is_file(), "icon.png must exist in $srcdir"

            pkg_name = "theme-forge-nebular-fusion-0.6.1-1-x86_64.pkg.tar.zst"
            pkg_path = Path(cwd) / pkg_name
            pkg_path.write_bytes(b"synthetic-nebular-pacman-package-bytes")
            return CommandReceipt(argv, 0, b"makepkg success\n", b"")

        def repo_add_handler(argv, cwd=None, env=None):
            db_path = Path(argv[1])
            db_path.parent.mkdir(parents=True, exist_ok=True)
            db_path.write_bytes(b"synthetic-repo-db-tar-gz")
            return CommandReceipt(argv, 0, b"repo-add success\n", b"")

        runner = MockCommandRunner(
            available_tools={"makepkg": "/usr/bin/makepkg", "repo-add": "/usr/bin/repo-add", "pacman":"/usr/bin/pacman"},
            handlers={"makepkg": makepkg_handler, "repo-add": repo_add_handler, "pacman":lambda argv,cwd,env:CommandReceipt(argv,0,b"glibc\n",b"")},
        )

        result = build_pacman_candidate(
            capture, intent, "x86_64", scratch, runner=runner
        )

        manifest = result["manifest"]
        derivation = result["derivation_record"]

        self.assertEqual(manifest["status"], "unsigned-candidate")
        self.assertEqual(manifest["architecture"], "x86_64")
        self.assertEqual(manifest["dependency_classification"], "native-tool-derived")
        self.assertIn("glibc", manifest["dependencies"])

        self.assertEqual(derivation["dependency_classification"], "native-tool-derived")
        self.assertIn("dt_needed_evidence", derivation["evidence"])
        self.assertIn("libc.so.6", derivation["evidence"]["dt_needed_evidence"]["system_sonames"])

    def test_rpm_builder_native_nebular_elf_and_rpm_query(self):
        neb_dir = self.root / "neb_rpm"
        neb_dir.mkdir()
        intent = fixture_evidence(neb_dir)
        capture = authenticate_release(selection_for_intent(intent), neb_dir)
        authorize_fixture_configuration(neb_dir, intent, capture)

        scratch = self.root / "scratch_neb_rpm"
        scratch.mkdir()

        def rpmbuild_handler(argv, cwd=None, env=None):
            spec_file = Path(argv[2])
            spec_content = spec_file.read_text("utf-8")
            self.assertIn("ExclusiveArch: x86_64", spec_content)
            self.assertIn("Requires: glibc", spec_content)

            rpm_dir = Path(cwd) / "RPMS" / "x86_64"
            rpm_dir.mkdir(parents=True, exist_ok=True)
            (rpm_dir / "theme-forge-nebular-fusion-0.6.1-1.fc43.x86_64.rpm").write_bytes(b"synthetic-neb-rpm")
            return CommandReceipt(argv, 0, b"rpmbuild success\n", b"")

        def rpm_handler(argv, cwd=None, env=None):
            if "--requires" in argv:
                out = b"libc.so.6()(64bit)\nrtld(GNU_HASH)\n"
                return CommandReceipt(argv, 0, out, b"")
            out = "theme-forge-nebular-fusion|0.6.1|1.fc43|x86_64|nebular123456789|sha256\n".encode()
            return CommandReceipt(argv, 0, out, b"")

        def rpmlint_handler(argv, cwd=None, env=None):
            return CommandReceipt(argv, 0, b"0 errors, 0 warnings.\n", b"")

        def createrepo_handler(argv, cwd=None, env=None):
            repodata = Path(argv[-1]) / "repodata"
            repodata.mkdir(parents=True, exist_ok=True)
            (repodata / "repomd.xml").write_bytes(b"<repomd/>")
            return CommandReceipt(argv, 0, b"createrepo_c complete\n", b"")

        runner = MockCommandRunner(
            available_tools={
                "rpmbuild": "/usr/bin/rpmbuild",
                "rpm": "/usr/bin/rpm",
                "rpmlint": "/usr/bin/rpmlint",
                "createrepo_c": "/usr/bin/createrepo_c",
            },
            handlers={
                "rpmbuild": rpmbuild_handler,
                "rpm": rpm_handler,
                "rpmlint": rpmlint_handler,
                "createrepo_c": createrepo_handler,
            },
        )

        result = build_rpm_candidate(
            capture, intent, "x86_64", scratch, runner=runner
        )

        manifest = result["manifest"]
        derivation = result["derivation_record"]

        self.assertEqual(manifest["architecture"], "x86_64")
        self.assertEqual(manifest["dependency_classification"], "native-tool-derived")
        self.assertIn("libc.so.6()(64bit)", manifest["dependencies"])
        self.assertIn("glibc", derivation["evidence"]["policy_dependencies"])
        self.assertEqual(len(derivation["tool_receipts"]), 5)
        self.assertIn("rpm_query_evidence", derivation["evidence"])
        self.assertIn("libc.so.6()(64bit)", derivation["evidence"]["rpm_query_evidence"]["requires"])

    def test_pacman_root_execution_refused(self):
        capture, intent, offline_npm = create_cli_fixture(self.root / "root_test")
        scratch = self.root / "scratch_root"
        scratch.mkdir()
        runner = MockCommandRunner(
            available_tools={"makepkg": "/usr/bin/makepkg", "repo-add": "/usr/bin/repo-add"}
        )
        with patch("os.geteuid", return_value=0):
            with self.assertRaises(ContractError) as caught:
                build_pacman_candidate(
                    capture, intent, "any", scratch, offline_npm_archives=offline_npm, runner=runner
                )
            self.assertEqual(caught.exception.code, "NONROOT_REQUIRED")


if __name__ == "__main__":
    unittest.main()
