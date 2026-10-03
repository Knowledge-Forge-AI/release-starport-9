"""Tests for candidate Pages assembly and prefix allowlist (rs9.pages_candidate)."""

import lzma
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from types import SimpleNamespace

from rs9.errors import ContractError
from rs9.pages import (
    CATEGORY_CANDIDATE_ASSET,
    CATEGORY_CNAME,
    CATEGORY_DOCS,
    CATEGORY_INDEX,
    CATEGORY_PUBLIC_KEY,
    classify_pages_path,
    scan_pages_tree,
    validate_pages_tree,
)
from rs9.pages_candidate import (
    assemble_pages_candidate,
)
from rs9.signing_fixture import SigningFixture, find_gpg_binary
from tests.pages_candidate_fixtures import construct_candidate_signed_tree


TRUTHFUL_ARMOR_PUBLIC_KEY = (
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
    "Version: RS9\n\n"
    "xo0EZVPxAAEEALU6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6\n"
    "Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6\n"
    "Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6Ojo6ABEBAAHN\n"
    "NFRoZW1lIEZvcmdlIFJlbGVhc2UgS2V5IDxyZWxlYXNlQGtub3dsZWRnZS1mb3Jn\n"
    "ZS5haT4=\n"
    "=g8c1\n"
    "-----END PGP PUBLIC KEY BLOCK-----\n"
)


def inventory(files):
    return {p: hashlib.sha256(v.encode() if isinstance(v, str) else v).hexdigest()
            for p, v in files.items()}


class PagesCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gpg_binary = find_gpg_binary()
        if cls.gpg_binary:
            try:
                with SigningFixture(gpg_binary=cls.gpg_binary):
                    pass
            except ContractError as error:
                if error.code == "GPG_AGENT_UNAVAILABLE":
                    cls.gpg_binary = None
                else:
                    raise

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_strict_required_prefix_paths_classification(self):
        # 1. APT prefix paths
        apt_cases = [
            ("apt/dists/resolute/Release", True, CATEGORY_CANDIDATE_ASSET),
            ("apt/dists/resolute/Release.gpg", True, CATEGORY_CANDIDATE_ASSET),
            ("apt/dists/resolute/InRelease", True, CATEGORY_CANDIDATE_ASSET),
            ("apt/dists/resolute/main/binary-amd64/Packages", True, CATEGORY_CANDIDATE_ASSET),
            ("apt/dists/resolute/main/binary-amd64/Packages.gz", True, CATEGORY_CANDIDATE_ASSET),
            ("apt/dists/resolute/main/binary-amd64/Packages.xz", True, CATEGORY_CANDIDATE_ASSET),
            ("apt/dists/resolute/by-hash/SHA256/" + "a" * 64, True, CATEGORY_CANDIDATE_ASSET),
            ("apt/pool/main/t/theme-forge/theme-forge_0.6.1_amd64.deb", True, CATEGORY_CANDIDATE_ASSET),
            ("apt/pool/main/t/theme-forge/theme-forge_0.6.1_arm64.deb", True, CATEGORY_CANDIDATE_ASSET),
        ]
        for path, exp_ok, exp_cat in apt_cases:
            with self.subTest(path=path):
                ok, cat = classify_pages_path(path)
                self.assertEqual(ok, exp_ok)
                self.assertEqual(cat, exp_cat)

        # 2. RPM prefix paths: rpm/fedora/43/{x86_64,aarch64}/{Packages,repodata} and rpm/rs9.repo
        rpm_cases = [
            ("rpm/rs9.repo", True, CATEGORY_CANDIDATE_ASSET),
            ("rpm/fedora/43/x86_64/Packages/theme-forge-0.6.1.x86_64.rpm", True, CATEGORY_CANDIDATE_ASSET),
            ("rpm/fedora/43/aarch64/Packages/theme-forge-0.6.1.aarch64.rpm", True, CATEGORY_CANDIDATE_ASSET),
            ("rpm/fedora/43/x86_64/repodata/repomd.xml", True, CATEGORY_CANDIDATE_ASSET),
            ("rpm/fedora/43/x86_64/repodata/repomd.xml.asc", True, CATEGORY_CANDIDATE_ASSET),
            ("rpm/fedora/43/x86_64/repodata/primary.xml.gz", True, CATEGORY_CANDIDATE_ASSET),
            ("rpm/fedora/43/x86_64/repodata/filelists.xml.gz", True, CATEGORY_CANDIDATE_ASSET),
            ("rpm/fedora/43/aarch64/repodata/repomd.xml", True, CATEGORY_CANDIDATE_ASSET),
            ("rpm/fedora/43/aarch64/repodata/primary.xml.gz", True, CATEGORY_CANDIDATE_ASSET),
        ]
        for path, exp_ok, exp_cat in rpm_cases:
            with self.subTest(path=path):
                ok, cat = classify_pages_path(path)
                self.assertEqual(ok, exp_ok)
                self.assertEqual(cat, exp_cat)

        # 3. Pacman prefix paths: pacman/x86_64 packages/db/files and exact signatures
        pacman_cases = [
            ("pacman/x86_64/theme-forge-0.6.1-1-x86_64.pkg.tar.zst", True, CATEGORY_CANDIDATE_ASSET),
            ("pacman/x86_64/theme-forge-0.6.1-1-x86_64.pkg.tar.zst.sig", True, CATEGORY_CANDIDATE_ASSET),
            ("pacman/x86_64/rs9.db", True, CATEGORY_CANDIDATE_ASSET),
            ("pacman/x86_64/rs9.db.sig", True, CATEGORY_CANDIDATE_ASSET),
            ("pacman/x86_64/rs9.db.tar.gz", True, CATEGORY_CANDIDATE_ASSET),
            ("pacman/x86_64/rs9.db.tar.gz.sig", True, CATEGORY_CANDIDATE_ASSET),
            ("pacman/x86_64/rs9.files", True, CATEGORY_CANDIDATE_ASSET),
            ("pacman/x86_64/rs9.files.sig", True, CATEGORY_CANDIDATE_ASSET),
            ("pacman/x86_64/rs9.files.tar.gz", True, CATEGORY_CANDIDATE_ASSET),
            ("pacman/x86_64/rs9.files.tar.gz.sig", True, CATEGORY_CANDIDATE_ASSET),
        ]
        for path, exp_ok, exp_cat in pacman_cases:
            with self.subTest(path=path):
                ok, cat = classify_pages_path(path)
                self.assertEqual(ok, exp_ok)
                self.assertEqual(cat, exp_cat)

        # 4. Keys prefix paths: keys/{rs9.asc,rs9-archive-keyring.gpg}
        key_cases = [
            ("keys/rs9.asc", True, CATEGORY_PUBLIC_KEY),
            ("keys/rs9-archive-keyring.gpg", True, CATEGORY_PUBLIC_KEY),
        ]
        for path, exp_ok, exp_cat in key_cases:
            with self.subTest(path=path):
                ok, cat = classify_pages_path(path)
                self.assertEqual(ok, exp_ok)
                self.assertEqual(cat, exp_cat)

        # 5. Docs prefix paths: docs/install
        doc_cases = [
            ("docs/install/index.html", True, CATEGORY_INDEX),
            ("docs/install/README.md", True, CATEGORY_DOCS),
            ("docs/install", True, CATEGORY_DOCS),
            ("docs/install/guide.html", True, CATEGORY_DOCS),
        ]
        for path, exp_ok, exp_cat in doc_cases:
            with self.subTest(path=path):
                ok, cat = classify_pages_path(path)
                self.assertEqual(ok, exp_ok)
                self.assertEqual(cat, exp_cat)

    def test_disallowed_paths_and_generic_suffix_bypass_rejected(self):
        disallowed = [
            # Arbitrary unreviewed locations
            "unreviewed/theme-forge.deb",
            "somewhere/theme-forge.rpm",
            "other/x86_64/pkg.pkg.tar.zst",
            "nested/deep/rs9.db.sig",
            "unknown/keys/rs9.asc",
            "random/dir/rs9.repo",
            # Wrong architecture or fedora version
            "rpm/fedora/42/x86_64/Packages/pkg.rpm",
            "rpm/fedora/43/i686/Packages/pkg.rpm",
            "pacman/aarch64/pkg.pkg.tar.zst",
            # Disallowed files under prefix dirs
            "rpm/fedora/43/x86_64/Packages/script.sh",
            "rpm/fedora/43/x86_64/repodata/database.sqlite",
            "pacman/x86_64/deploy.py",
            "apt/dists/resolute/Makefile",
            # Sensitive filename patterns rejected even under valid prefix dirs
            "rpm/fedora/43/x86_64/Packages/secret.rpm",
            "rpm/fedora/43/x86_64/Packages/private_pkg.rpm",
            "keys/secret.asc",
            "keys/id_rsa.pub",
            "apt/pool/token.deb",
            "pacman/x86_64/credential.db.sig",
            "pacman/x86_64/unreviewed/pkg.pkg.tar.zst",
            "rpm/fedora/43/x86_64/repodata/repomd.sh",
            "rpm/fedora/43/x86_64/repodata/unreviewed/primary.xml.gz",
            "rpm/unreviewed/index.html",
            "keys/Release.gpg",
            # Suffix alone cannot bypass directory check
            "rs9.repo",
            "repomd.xml",
            "rs9-archive-keyring.gpg",
        ]
        for path in disallowed:
            with self.subTest(path=path):
                ok, _ = classify_pages_path(path)
                self.assertFalse(ok)

    def test_secret_packets_cannot_use_package_suffix_as_exemption(self):
        tree = self.root / "secret_packet_tree"
        package = tree / "rpm/fedora/43/x86_64/Packages/sample.rpm"
        package.parent.mkdir(parents=True)
        package.write_bytes(bytes([0xc5, 1, 0]))
        with self.assertRaises(ContractError) as raised:
            scan_pages_tree(tree)
        self.assertEqual(raised.exception.code, "CREDENTIAL_DETECTED")

    def test_secret_key_in_keys_path_never_suppressed(self):
        keys_dir = self.root / "keys_test_tree"
        keys_dir.mkdir()

        # Place ASCII secret key block in keys/rs9.asc
        secret_key_file = keys_dir / "keys/rs9.asc"
        keys_dir.joinpath("keys").mkdir()
        secret_armor = (
            "-----BEGIN PGP SECRET KEY BLOCK-----\n"
            "Version: Test\n\n"
            "fake-secret-material\n"
            "-----END PGP SECRET KEY BLOCK-----\n"
        )
        secret_key_file.write_text(secret_armor)

        with self.assertRaises(ContractError) as ctx:
            scan_pages_tree(keys_dir)
        self.assertEqual(ctx.exception.code, "CREDENTIAL_DETECTED")

        # Place binary secret packet in keys/rs9-archive-keyring.gpg
        secret_key_file.unlink()
        binary_key_file = keys_dir / "keys/rs9-archive-keyring.gpg"
        tag5_new = bytes([0xC0 | 5, 4, 1, 2, 3, 4])
        binary_key_file.write_bytes(tag5_new)

        with self.assertRaises(ContractError) as ctx:
            scan_pages_tree(keys_dir)
        self.assertEqual(ctx.exception.code, "CREDENTIAL_DETECTED")

    def test_pages_candidate_assembly_binds_exact_inventory(self):
        scratch = self.root / "scratch_candidate"
        scratch.mkdir()

        files = {
            "CNAME": "rs9.knowledge-forge.ai\n",
            "index.html": "<!DOCTYPE html><html><body>RS9</body></html>\n",
            "README.md": "# Candidate Mirror\n",
            "docs/install/index.html": "<!DOCTYPE html><html><body>Install</body></html>\n",
            "rpm/rs9.repo": "[rs9]\nname=rs9\nbaseurl=https://rs9.knowledge-forge.ai/\n",
            "keys/rs9.asc": TRUTHFUL_ARMOR_PUBLIC_KEY,
            "keys/rs9-archive-keyring.gpg": bytes([0xC0 | 6, 2, 10, 20]),
        }

        cand = assemble_pages_candidate(scratch, files=files, exact_inventory=inventory(files))
        self.assertTrue(cand.is_candidate)
        self.assertFalse(cand.is_live)
        self.assertEqual(cand.status()["file_count"], 7)

        # Mismatch: test unmanifested file added
        unmanifested = scratch / "docs/unmanifested.md"
        unmanifested.write_text("# Unmanifested\n")
        with self.assertRaises(ContractError) as ctx:
            validate_pages_tree(scratch, manifest=cand.exact_inventory)
        self.assertEqual(ctx.exception.code, "UNMANIFESTED_FILE")
        unmanifested.unlink()

        # Mismatch: test tampered file
        (scratch / "index.html").write_text("<script>alert('tamper');</script>")
        with self.assertRaises(ContractError) as ctx:
            validate_pages_tree(scratch, manifest=cand.exact_inventory)
        self.assertEqual(ctx.exception.code, "TAMPER_DETECTED")

    def test_pages_candidate_never_deploys(self):
        scratch = self.root / "scratch_no_deploy"
        scratch.mkdir()

        files = {
            "CNAME": "rs9.knowledge-forge.ai\n",
            "index.html": "<!DOCTYPE html><html><body>RS9</body></html>\n",
            "keys/rs9.asc": TRUTHFUL_ARMOR_PUBLIC_KEY,
        }
        cand = assemble_pages_candidate(scratch, files=files, exact_inventory=inventory(files))

        with self.assertRaises(ContractError) as ctx:
            cand.deploy()
        self.assertEqual(ctx.exception.code, "DEPLOYMENT_FORBIDDEN")

        with self.assertRaises(ContractError) as ctx:
            cand.publish()
        self.assertEqual(ctx.exception.code, "DEPLOYMENT_FORBIDDEN")

        with self.assertRaises(ContractError) as ctx:
            cand.claim_live()
        self.assertEqual(ctx.exception.code, "DEPLOYMENT_FORBIDDEN")

    def test_scratch_must_be_empty_to_assemble(self):
        scratch = self.root / "non_empty_scratch"
        scratch.mkdir()
        (scratch / "leftover.txt").write_text("prior state")

        with self.assertRaises(ContractError) as ctx:
            assemble_pages_candidate(scratch, files={"CNAME": "rs9.example.com\n"})
        self.assertEqual(ctx.exception.code, "SCRATCH_NOT_EMPTY")

    def test_inventory_required_or_explicitly_non_authoritative(self):
        scratch = self.root / "inventory_required"
        scratch.mkdir()
        files = {"index.html": "RS9"}
        with self.assertRaises(ContractError) as raised:
            assemble_pages_candidate(scratch, files=files)
        self.assertEqual(raised.exception.code, "MANIFEST_REQUIRED")
        self.assertEqual(list(scratch.iterdir()), [])
        candidate = assemble_pages_candidate(scratch, files=files, require_exact_inventory=False)
        self.assertFalse(candidate.manifest["authoritative"])
        self.assertEqual(candidate.status()["inventory_binding"], "discovery")

    def test_inventory_is_checked_before_writes(self):
        for expected, code in (({"index.html": "a" * 64}, "TAMPER_DETECTED"),
                               ({}, "UNMANIFESTED_FILE"),
                               ({"docs/missing.md": "a" * 64}, "MISSING_MANIFESTED_FILE")):
            with self.subTest(code=code):
                scratch = self.root / code
                scratch.mkdir()
                with self.assertRaises(ContractError) as raised:
                    assemble_pages_candidate(scratch, files={"index.html": "RS9"}, exact_inventory=expected)
                self.assertEqual(raised.exception.code, code)
                self.assertEqual(list(scratch.iterdir()), [])

    def test_sources_cannot_override_repository_key_or_cname(self):
        apt = self.root / "apt-source"
        apt.mkdir()
        (apt / "Release").write_bytes(b"original")
        store = SimpleNamespace(list_records=lambda **kw: [{"rel_path": "rpm/rs9.repo"}],
                                get=lambda *args, **kw: ({}, b"original"))
        fixture = SimpleNamespace(public_key_bytes=b"public", public_key_binary=b"public")
        cases = [({"apt_repo": SimpleNamespace(root=apt)}, "apt/Release"),
                 ({"signed_store": store}, "rpm/rs9.repo"),
                 ({"signing_fixture": fixture}, "keys/rs9.asc"),
                 ({"cname": "rs9.knowledge-forge.ai"}, "CNAME")]
        for i, (kwargs, path) in enumerate(cases):
            scratch = self.root / f"collision-{i}"
            scratch.mkdir()
            with self.assertRaises(ContractError) as raised:
                assemble_pages_candidate(scratch, files={path: b"replacement"}, **kwargs)
            self.assertEqual(raised.exception.code, "CANDIDATE_COLLISION")
            self.assertEqual(list(scratch.iterdir()), [])

    def test_cname_is_bound_to_rs9_origin(self):
        for i, kwargs in enumerate(({"cname": "other.example.com"},
                                    {"files": {"CNAME": "other.example.com\n"}})):
            scratch = self.root / f"cname-{i}"
            scratch.mkdir()
            with self.assertRaises(ContractError) as raised:
                assemble_pages_candidate(scratch, **kwargs)
            self.assertEqual(raised.exception.code, "CANDIDATE_CNAME")
            self.assertEqual(list(scratch.iterdir()), [])

    def test_legacy_namespaces_are_rejected(self):
        paths = ["dists/resolute/Release", "pool/main/pkg.deb", "by-hash/SHA256/" + "a" * 64,
                 "repodata/repomd.xml", "rpm/pkg.rpm", "rpm/packages/pkg.rpm", "packages/pkg.rpm",
                 "arch/pkg.pkg.tar.zst", "archlinux/rs9.db", "core/os/x86_64/core.db",
                 "assets/pkg.tar.gz", "notes.md", "pubkey.gpg", "assets/index.html"]
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(classify_pages_path(path), (False, ""))

    def test_construct_candidate_signed_tree_with_fixture(self):
        if not self.gpg_binary:
            self.skipTest("GnuPG binary not available")

        scratch = self.root / "fixture_signed_scratch"
        scratch.mkdir()

        with SigningFixture(gpg_binary=self.gpg_binary) as fixture:
            cand = construct_candidate_signed_tree(scratch, signing_fixture=fixture)
            status = cand.status()
            self.assertTrue(status["is_candidate"])
            self.assertFalse(status["is_live"])
            self.assertEqual(status["qualification"], "pending")
            self.assertIn("keys/rs9.asc", cand.exact_inventory)
            self.assertIn("keys/rs9-archive-keyring.gpg", cand.exact_inventory)
            self.assertIn("rpm/fedora/43/x86_64/repodata/repomd.xml.asc", cand.exact_inventory)
            self.assertIn("pacman/x86_64/rs9.db.sig", cand.exact_inventory)

            # Verify repomd.xml detached signature using fixture
            repomd_xml = (scratch / "rpm/fedora/43/x86_64/repodata/repomd.xml").read_bytes()
            repomd_asc = (scratch / "rpm/fedora/43/x86_64/repodata/repomd.xml.asc").read_bytes()
            ver = fixture.verify(repomd_xml, repomd_asc)
            self.assertEqual(ver["status"], "valid")
            self.assertEqual(ver["verified_issuer"], fixture.primary_fingerprint)


if __name__ == "__main__":
    unittest.main()
