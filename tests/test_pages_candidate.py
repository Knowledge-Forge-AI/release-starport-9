"""Tests for candidate Pages assembly and prefix allowlist (rs9.pages_candidate)."""

import lzma
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
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
import json

from rs9.pages import merkle_inventory
from rs9.pages_candidate import (
    CUSTODY_MANIFEST,
    NONPRODUCTION_BANNER,
    PAGES_HOST,
    REQUIRED_PAGES_FILES,
    assemble_pages_candidate,
    collect_candidate_sources,
    exact_inventory_for,
    load_custody_bundle,
    render_install_docs,
    verify_pages_completeness,
    verify_public_tree_modes,
    write_custody_bundle,
)
from rs9.repo_apt import AptRepositoryCandidate
from rs9.scratch import canonical
from rs9.signing_fixture import SigningFixture, find_gpg_binary
from tests.pages_candidate_fixtures import construct_candidate_signed_tree
from tests.test_repo_apt import FixtureSigner, build_minimal_deb


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


class HermeticSigningDouble(FixtureSigner):
    """Key-bound fixture-signer double with truthful OpenPGP public key packets."""

    def __init__(self, fingerprint: str = "A" * 40, homedir: Path | None = None) -> None:
        super().__init__(fingerprint)
        self.public_key_armor = TRUTHFUL_ARMOR_PUBLIC_KEY
        self.public_key_bytes = TRUTHFUL_ARMOR_PUBLIC_KEY.encode("utf-8")
        self.public_key_binary = bytes([0xC0 | 6, 2, 10, 20])
        self.homedir = homedir
        self.gpg = "gpg"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


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
            ("keys/rs9-candidate-fixture-NONPRODUCTION.asc", True, CATEGORY_PUBLIC_KEY),
            ("keys/rs9-candidate-fixture-NONPRODUCTION.gpg", True, CATEGORY_PUBLIC_KEY),
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
            "unknown/keys/rs9-candidate-fixture-NONPRODUCTION.asc",
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

        # Place ASCII secret key block in keys/rs9-candidate-fixture-NONPRODUCTION.asc
        secret_key_file = keys_dir / "keys/rs9-candidate-fixture-NONPRODUCTION.asc"
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

        # Place binary secret packet in keys/rs9-candidate-fixture-NONPRODUCTION.gpg
        secret_key_file.unlink()
        binary_key_file = keys_dir / "keys/rs9-candidate-fixture-NONPRODUCTION.gpg"
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
            "keys/rs9-candidate-fixture-NONPRODUCTION.asc": TRUTHFUL_ARMOR_PUBLIC_KEY,
            "keys/rs9-candidate-fixture-NONPRODUCTION.gpg": bytes([0xC0 | 6, 2, 10, 20]),
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
            "keys/rs9-candidate-fixture-NONPRODUCTION.asc": TRUTHFUL_ARMOR_PUBLIC_KEY,
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
        fixture = SimpleNamespace(public_key_bytes=b"public", public_key_binary=b"public", primary_fingerprint="A"*40)
        cases = [({"apt_repo": SimpleNamespace(root=apt)}, "apt/Release"),
                 ({"signed_store": store}, "rpm/rs9.repo"),
                 ({"signing_fixture": fixture}, "keys/rs9-candidate-fixture-NONPRODUCTION.asc"),
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
            self.assertIn("keys/rs9-candidate-fixture-NONPRODUCTION.asc", cand.exact_inventory)
            self.assertIn("keys/rs9-candidate-fixture-NONPRODUCTION.gpg", cand.exact_inventory)
            self.assertIn("rpm/fedora/43/x86_64/repodata/repomd.xml.asc", cand.exact_inventory)
            self.assertIn("pacman/x86_64/rs9.db.sig", cand.exact_inventory)

            # Verify repomd.xml detached signature using fixture
            repomd_xml = (scratch / "rpm/fedora/43/x86_64/repodata/repomd.xml").read_bytes()
            repomd_asc = (scratch / "rpm/fedora/43/x86_64/repodata/repomd.xml.asc").read_bytes()
            ver = fixture.verify(repomd_xml, repomd_asc)
            self.assertEqual(ver["status"], "valid")
            self.assertEqual(ver["verified_issuer"], fixture.primary_fingerprint)
            # The bound inventory is exactly committed by the Merkle root.
            self.assertEqual(status["merkle_root"], merkle_inventory(cand.exact_inventory)["root"])

    def test_construct_candidate_signed_tree_hermetic(self):
        scratch = self.root / "hermetic_fixture_signed_scratch"
        scratch.mkdir()

        fixture = HermeticSigningDouble(homedir=self.root / "fixture-home")
        cand = construct_candidate_signed_tree(scratch, signing_fixture=fixture)
        status = cand.status()
        self.assertTrue(status["is_candidate"])
        self.assertFalse(status["is_live"])
        self.assertEqual(status["qualification"], "pending")
        self.assertIn("keys/rs9-candidate-fixture-NONPRODUCTION.asc", cand.exact_inventory)
        self.assertIn("keys/rs9-candidate-fixture-NONPRODUCTION.gpg", cand.exact_inventory)
        self.assertIn("keys/KEY-METADATA.json", cand.exact_inventory)
        self.assertIn("rpm/rs9.repo", cand.exact_inventory)
        self.assertIn("rpm/fedora/43/x86_64/repodata/repomd.xml.asc", cand.exact_inventory)
        self.assertIn("pacman/x86_64/rs9.db.sig", cand.exact_inventory)

        # Verify repo sample config uses nonproduction candidate name and key path
        repo_text = (scratch / "rpm/rs9.repo").read_text()
        self.assertIn("[rs9-fedora-nonproduction]", repo_text)
        self.assertIn("repo_gpgcheck=1", repo_text)
        self.assertIn("keys/rs9-candidate-fixture-NONPRODUCTION.asc", repo_text)

        # Verify repomd.xml detached signature using fixture
        repomd_xml = (scratch / "rpm/fedora/43/x86_64/repodata/repomd.xml").read_bytes()
        repomd_asc = (scratch / "rpm/fedora/43/x86_64/repodata/repomd.xml.asc").read_bytes()
        ver = fixture.verify(repomd_xml, repomd_asc)
        self.assertEqual(ver["status"], "valid")
        self.assertEqual(ver["verified_issuer"], fixture.primary_fingerprint)
        # The bound inventory is exactly committed by the Merkle root.
        self.assertEqual(status["merkle_root"], merkle_inventory(cand.exact_inventory)["root"])

    def test_fixture_inventory_detects_assembler_public_armor_drift(self):
        fixture = HermeticSigningDouble()
        scratch = self.root / "armor_drift"; scratch.mkdir()
        with patch("rs9.pages_candidate._fixture_public_armor",
                   return_value=fixture.public_key_bytes + b"\n"), self.assertRaises(ContractError) as caught:
            construct_candidate_signed_tree(scratch, signing_fixture=fixture)
        self.assertEqual(caught.exception.code, "TAMPER_DETECTED")

    def test_candidate_fixture_inventory_regressions(self):
        fixture = HermeticSigningDouble()

        # 1. Custom files supplying production key paths are strictly rejected
        for bad_key in ("keys/rs9.asc", "keys/rs9-archive-keyring.gpg"):
            with self.subTest(bad_key=bad_key):
                sub_scratch = self.root / f"bad_key_{bad_key.replace('/', '_')}"
                sub_scratch.mkdir()
                with self.assertRaises(ContractError) as caught:
                    construct_candidate_signed_tree(
                        sub_scratch,
                        signing_fixture=fixture,
                        custom_files={bad_key: b"unallowed"},
                    )
                self.assertEqual(caught.exception.code, "FIXTURE_KEY_PATH")

        # 2. Tampered file fails exact inventory check
        sub_scratch2 = self.root / "tampered_candidate"
        sub_scratch2.mkdir()
        with self.assertRaises(ContractError) as caught:
            assemble_pages_candidate(
                sub_scratch2,
                files={"index.html": "<!DOCTYPE html><html><body>Original</body></html>\n"},
                signing_fixture=fixture,
                exact_inventory={
                    "index.html": "0" * 64,  # wrong hash
                    "CNAME": hashlib.sha256(b"rs9.knowledge-forge.ai\n").hexdigest(),
                    "keys/rs9-candidate-fixture-NONPRODUCTION.asc": hashlib.sha256(fixture.public_key_bytes).hexdigest(),
                    "keys/rs9-candidate-fixture-NONPRODUCTION.gpg": hashlib.sha256(fixture.public_key_binary).hexdigest(),
                    "keys/KEY-METADATA.json": hashlib.sha256(canonical({
                        "production": False, "fixture": True, "fingerprint": fixture.primary_fingerprint,
                        "purpose": "NON-PRODUCTION CANDIDATE TEST ONLY",
                    })).hexdigest(),
                },
                cname="rs9.knowledge-forge.ai",
            )
        self.assertEqual(caught.exception.code, "TAMPER_DETECTED")

    def test_fixture_metadata_omission_and_extra_declaration_fail_exact_inventory(self):
        fixture = HermeticSigningDouble()
        original = self.root / "original"
        original.mkdir()
        candidate = construct_candidate_signed_tree(original, signing_fixture=fixture)
        files = {p: (original / p).read_bytes() for p in candidate.exact_inventory if not p.startswith("keys/") and p != "CNAME"}
        for case, code in (("omitted", "UNMANIFESTED_FILE"), ("extra", "MISSING_MANIFESTED_FILE")):
            with self.subTest(case=case):
                target = self.root / case
                target.mkdir()
                declared = dict(candidate.exact_inventory)
                if case == "omitted":
                    del declared["keys/KEY-METADATA.json"]
                else:
                    declared["keys/extra-NONPRODUCTION.asc"] = "a" * 64
                with self.assertRaises(ContractError) as caught:
                    assemble_pages_candidate(target, files=files, signing_fixture=fixture, exact_inventory=declared,
                                             cname="rs9.knowledge-forge.ai")
                self.assertEqual(caught.exception.code, code)

    def test_assemble_pages_candidate_public_modes_under_both_umasks(self):
        docs = render_install_docs()
        sources = collect_candidate_sources(files=dict(docs), cname=PAGES_HOST)
        exact_inv = exact_inventory_for(sources)

        for mask in (0o022, 0o077):
            old_umask = os.umask(mask)
            try:
                ancestor = self.root / f"ancestor_pages_{mask:o}"
                ancestor.mkdir(mode=0o700)
                os.chmod(ancestor, 0o700)
                scratch = ancestor / "assembled"
                scratch.mkdir(mode=0o700)
                os.chmod(scratch, 0o700)

                cand = assemble_pages_candidate(
                    scratch,
                    files=dict(docs),
                    cname=PAGES_HOST,
                    exact_inventory=exact_inv,
                )

                self.assertEqual(ancestor.stat().st_mode & 0o777, 0o700, f"Ancestor modified under umask {oct(mask)}")
                self.assertEqual(scratch.stat().st_mode & 0o777, 0o755, f"Root not 0755 under umask {oct(mask)}")

                report = verify_public_tree_modes(scratch)
                self.assertEqual(report["status"], "pass")
                self.assertEqual(report["mismatch_counts"]["file_mode_mismatches"], 0)
                self.assertEqual(report["mismatch_counts"]["dir_mode_mismatches"], 0)
                self.assertEqual(report["mismatch_counts"]["special_or_symlink_objects"], 0)
            finally:
                os.umask(old_umask)

    def test_pages_candidate_byte_and_hash_invariance_under_both_umasks(self):
        runs = {}
        for mask in (0o022, 0o077):
            old_umask = os.umask(mask)
            try:
                fixture = HermeticSigningDouble(homedir=self.root / f"fx_home_{mask:o}")
                scratch = self.root / f"invariance_cand_{mask:o}"
                scratch.mkdir()
                cand = construct_candidate_signed_tree(scratch, signing_fixture=fixture)

                file_data = {}
                for cur, _, fnames in os.walk(scratch):
                    cur_p = Path(cur)
                    for f in fnames:
                        fp = cur_p / f
                        rel = fp.relative_to(scratch).as_posix()
                        content = fp.read_bytes()
                        file_data[rel] = {
                            "bytes": content,
                            "sha256": hashlib.sha256(content).hexdigest(),
                            "mode": fp.stat().st_mode & 0o777,
                        }
                runs[mask] = {
                    "cand": cand,
                    "files": file_data,
                    "merkle_root": cand.status()["merkle_root"],
                    "exact_inventory": cand.exact_inventory,
                }
            finally:
                os.umask(old_umask)

        self.assertEqual(sorted(runs[0o022]["files"]), sorted(runs[0o077]["files"]))
        for rel in sorted(runs[0o022]["files"]):
            f022 = runs[0o022]["files"][rel]
            f077 = runs[0o077]["files"][rel]
            self.assertEqual(f022["bytes"], f077["bytes"], f"Byte mismatch on {rel}")
            self.assertEqual(f022["sha256"], f077["sha256"], f"SHA256 mismatch on {rel}")
            self.assertEqual(f022["mode"], 0o644)
            self.assertEqual(f077["mode"], 0o644)

        self.assertEqual(runs[0o022]["merkle_root"], runs[0o077]["merkle_root"])
        self.assertEqual(runs[0o022]["exact_inventory"], runs[0o077]["exact_inventory"])

    def test_pages_candidate_with_apt_repo_staging_projection_under_both_umasks(self):
        deb_bytes = build_minimal_deb("tf-test", "1.0.0", "amd64", payload_content=b"test-content-for-apt-pages")
        runs = {}

        for mask in (0o022, 0o077):
            old_umask = os.umask(mask)
            try:
                ancestor = self.root / f"anc_proj_{mask:o}"
                ancestor.mkdir(mode=0o700)
                os.chmod(ancestor, 0o700)

                apt_dir = ancestor / "apt_repo"
                apt_dir.mkdir(mode=0o700)
                os.chmod(apt_dir, 0o700)

                repo = AptRepositoryCandidate(apt_dir)
                repo.add_package(deb_bytes=deb_bytes)
                repo.build_indices()
                fixture = HermeticSigningDouble(homedir=self.root / f"fx_apt_proj_{mask:o}")
                repo.sign_with_fixture(fixture)

                self.assertEqual(ancestor.stat().st_mode & 0o777, 0o700)
                self.assertEqual(apt_dir.stat().st_mode & 0o777, 0o755)
                apt_report = verify_public_tree_modes(apt_dir)
                self.assertEqual(apt_report["status"], "pass")

                pages_dir = ancestor / "pages_staging"
                pages_dir.mkdir(mode=0o700)
                os.chmod(pages_dir, 0o700)

                docs = render_install_docs()
                sources = collect_candidate_sources(
                    files=dict(docs),
                    apt_repo=repo,
                    cname=PAGES_HOST,
                    signing_fixture=fixture,
                )
                exact_inv = exact_inventory_for(sources)
                cand = assemble_pages_candidate(
                    pages_dir,
                    files=dict(docs),
                    apt_repo=repo,
                    cname=PAGES_HOST,
                    signing_fixture=fixture,
                    exact_inventory=exact_inv,
                )

                self.assertEqual(ancestor.stat().st_mode & 0o777, 0o700)
                self.assertEqual(pages_dir.stat().st_mode & 0o777, 0o755)
                pages_report = verify_public_tree_modes(pages_dir)
                self.assertEqual(pages_report["status"], "pass")

                files = {}
                for cur, _, fnames in os.walk(pages_dir):
                    cur_p = Path(cur)
                    for f in fnames:
                        fp = cur_p / f
                        rel = fp.relative_to(pages_dir).as_posix()
                        content = fp.read_bytes()
                        files[rel] = {
                            "bytes": content,
                            "sha256": hashlib.sha256(content).hexdigest(),
                            "mode": fp.stat().st_mode & 0o777,
                        }
                runs[mask] = {
                    "cand": cand,
                    "files": files,
                    "merkle_root": cand.status()["merkle_root"],
                    "exact_inventory": cand.exact_inventory,
                }
            finally:
                os.umask(old_umask)

        self.assertEqual(sorted(runs[0o022]["files"]), sorted(runs[0o077]["files"]))
        apt_files = [p for p in runs[0o022]["files"] if p.startswith("apt/")]
        self.assertTrue(any("pool/main" in p for p in apt_files))
        self.assertTrue(any("Packages" in p for p in apt_files))
        self.assertTrue(any("InRelease" in p for p in apt_files))
        self.assertTrue(any("by-hash" in p for p in apt_files))

        for rel in sorted(runs[0o022]["files"]):
            f022 = runs[0o022]["files"][rel]
            f077 = runs[0o077]["files"][rel]
            self.assertEqual(f022["bytes"], f077["bytes"], f"Byte mismatch on {rel}")
            self.assertEqual(f022["sha256"], f077["sha256"], f"SHA256 mismatch on {rel}")
            self.assertEqual(f022["mode"], 0o644)
            self.assertEqual(f077["mode"], 0o644)

        self.assertEqual(runs[0o022]["merkle_root"], runs[0o077]["merkle_root"])

    def test_verify_public_tree_modes_detects_tamper_and_mode_defects(self):
        docs = render_install_docs()
        sources = collect_candidate_sources(files=dict(docs), cname=PAGES_HOST)
        scratch = self.root / "tamper_scratch"
        scratch.mkdir()
        assemble_pages_candidate(scratch, files=dict(docs), cname=PAGES_HOST, exact_inventory=exact_inventory_for(sources))

        report = verify_public_tree_modes(scratch)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["mismatch_counts"]["file_mode_mismatches"], 0)
        self.assertEqual(report["mismatch_counts"]["dir_mode_mismatches"], 0)

        os.chmod(scratch / "CNAME", 0o600)
        report = verify_public_tree_modes(scratch)
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["mismatch_counts"]["file_mode_mismatches"], 1)
        self.assertTrue(any(sample["path"].endswith("CNAME") for sample in report["mismatch_samples"]["file_mode"]))
        os.chmod(scratch / "CNAME", 0o644)

        os.chmod(scratch / "docs", 0o700)
        report = verify_public_tree_modes(scratch)
        self.assertEqual(report["status"], "fail")
        self.assertGreaterEqual(report["mismatch_counts"]["dir_mode_mismatches"], 1)
        os.chmod(scratch / "docs", 0o755)

        os.symlink(scratch / "CNAME", scratch / "symlink_file")
        try:
            report = verify_public_tree_modes(scratch)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["mismatch_counts"]["special_or_symlink_objects"], 1)
        finally:
            (scratch / "symlink_file").unlink()

    def test_assemble_pages_candidate_refuses_symlink_target(self):
        real_target = self.root / "real_target"
        real_target.mkdir()
        sym_target = self.root / "sym_target"
        try:
            os.symlink(real_target, sym_target)
        except OSError:
            self.skipTest("Symlinks not supported")

        with self.assertRaises(ContractError) as caught:
            assemble_pages_candidate(sym_target, files={"index.html": b"hello"})
        self.assertEqual(caught.exception.code, "SYMLINK_REJECTED")


class CustodyAndCompletenessTests(unittest.TestCase):
    AUTH = "a" * 64
    COMMIT = "b" * 40

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        self.temp_dir.cleanup()

    def bundle(self, name: str = "deb-amd64", family: str = "deb", packages=None) -> Path:
        target = self.root / name
        target.mkdir()
        write_custody_bundle(
            target, family=family, system="amd64",
            packages=packages or {"tf-cli_1.0-1_all.deb": b"deb-one", "tf-nebular_1.0-1_amd64.deb": b"deb-two"},
            authentication_sha256=self.AUTH, source_commit=self.COMMIT)
        return target

    def rewrite_manifest(self, target: Path, **changes) -> None:
        manifest = json.loads((target / CUSTODY_MANIFEST).read_bytes())
        manifest.update(changes)
        (target / CUSTODY_MANIFEST).write_bytes(canonical(manifest))

    def test_round_trip_is_exact_and_nonproduction(self):
        target = self.bundle()
        loaded = load_custody_bundle(target, expected_family="deb", expected_authentication_sha256=self.AUTH)
        manifest = loaded["manifest"]
        self.assertTrue(manifest["nonproduction"])
        self.assertFalse(manifest["production_enabled"])
        self.assertEqual(sorted(loaded["packages"]), ["tf-cli_1.0-1_all.deb", "tf-nebular_1.0-1_amd64.deb"])
        self.assertEqual(loaded["packages"]["tf-cli_1.0-1_all.deb"].read_bytes(), b"deb-one")
        self.assertEqual(manifest["merkle"], merkle_inventory(
            {name: row["sha256"] for name, row in manifest["files"].items()}))
        self.assertEqual(sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()),
                         [CUSTODY_MANIFEST, "files/tf-cli_1.0-1_all.deb", "files/tf-nebular_1.0-1_amd64.deb"])

    def test_write_accepts_only_unsigned_package_bytes_for_the_family(self):
        cases = [
            {"family": "other", "packages": {"a.deb": b"x"}},
            {"family": "deb", "packages": {}},
            {"family": "deb", "packages": {"a.deb.sig": b"x"}},
            {"family": "deb", "packages": {"InRelease": b"x"}},
            {"family": "deb", "packages": {"a.rpm": b"x"}},
            {"family": "rpm", "packages": {"a.deb": b"x"}},
            {"family": "deb", "packages": {"../a.deb": b"x"}},
            {"family": "deb", "packages": {"a.deb": b""}},
            {"family": "deb", "packages": {"a.deb": "text"}},
        ]
        for i, case in enumerate(cases):
            target = self.root / f"bad-{i}"
            target.mkdir()
            with self.subTest(case=case), self.assertRaises(ContractError):
                write_custody_bundle(target, system="amd64", authentication_sha256=None, source_commit=None, **case)
        for family, name in (("rpm", "a.rpm"), ("pacman", "a-1-1-x86_64.pkg.tar.zst")):
            target = self.root / f"ok-{family}"
            target.mkdir()
            write_custody_bundle(target, family=family, system="x86_64-linux", packages={name: b"bytes"},
                                 authentication_sha256=None, source_commit=None)
        target = self.root / "bad-auth"
        target.mkdir()
        with self.assertRaises(ContractError):
            write_custody_bundle(target, family="deb", system="amd64", packages={"a.deb": b"x"},
                                 authentication_sha256="short", source_commit=None)

    def test_load_rejects_every_deviation_from_the_exact_custody_tree(self):
        def case(name, mutate, code):
            target = self.bundle(name)
            mutate(target)
            with self.subTest(case=name), self.assertRaises(ContractError) as caught:
                load_custody_bundle(target, expected_authentication_sha256=self.AUTH)
            self.assertEqual(caught.exception.code, code)

        case("no-manifest", lambda t: (t / CUSTODY_MANIFEST).unlink(), "CUSTODY_MISSING")
        case("tampered", lambda t: (t / "files/tf-cli_1.0-1_all.deb").write_bytes(b"deb-ONE"), "TAMPER_DETECTED")
        case("extra-signature", lambda t: (t / "files/tf-cli_1.0-1_all.deb.asc").write_bytes(b"sig"), "CUSTODY_INVENTORY")
        case("extra-root-file", lambda t: (t / "notes.txt").write_bytes(b"x"), "CUSTODY_INVENTORY")
        case("missing-package", lambda t: (t / "files/tf-cli_1.0-1_all.deb").unlink(), "CUSTODY_INVENTORY")
        case("wrong-merkle", lambda t: self.rewrite_manifest(
            t, merkle={**json.loads((t / CUSTODY_MANIFEST).read_bytes())["merkle"], "root": "0" * 64}), "MERKLE_MISMATCH")
        case("production-flag", lambda t: self.rewrite_manifest(t, production_enabled=True), "CUSTODY_POLICY")
        case("not-nonproduction", lambda t: self.rewrite_manifest(t, nonproduction=False), "CUSTODY_POLICY")
        case("extra-key", lambda t: self.rewrite_manifest(t, extra=1), "CUSTODY_SCHEMA")
        case("bad-family", lambda t: self.rewrite_manifest(t, family="zip"), "CUSTODY_SCHEMA")
        case("wrong-provenance", lambda t: self.rewrite_manifest(t, authentication_sha256="c" * 64), "HOSTED_PROVENANCE")
        case("malformed", lambda t: (t / CUSTODY_MANIFEST).write_bytes(b"{not json"), "CUSTODY_SCHEMA")
        with self.assertRaises(ContractError) as caught:
            load_custody_bundle(self.bundle("family-check"), expected_family="rpm")
        self.assertEqual(caught.exception.code, "CUSTODY_SCHEMA")

    def test_symlinked_custody_package_is_rejected(self):
        target = self.bundle("symlink")
        victim = target / "files/tf-cli_1.0-1_all.deb"
        victim.unlink()
        try:
            os.symlink(target / "files/tf-nebular_1.0-1_amd64.deb", victim)
        except OSError:
            self.skipTest("Symlinks not supported on this filesystem")
        with self.assertRaises(ContractError) as caught:
            load_custody_bundle(target)
        self.assertEqual(caught.exception.code, "SYMLINK_REJECTED")

    def test_completeness_requires_every_document_key_and_family_object(self):
        families = {
            "apt": ["apt/dists/resolute/Release", "apt/dists/resolute/InRelease", "apt/dists/resolute/Release.gpg"],
            "rpm": [f"rpm/fedora/43/{a}/repodata/{n}" for a in ("x86_64", "aarch64") for n in ("repomd.xml", "repomd.xml.asc")],
            "pacman": ["pacman/x86_64/rs9.db.tar.gz", "pacman/x86_64/rs9.db.tar.gz.sig"],
        }
        inventory = {path: "a" * 64 for path in [*REQUIRED_PAGES_FILES, *sum(families.values(), [])]}
        verify_pages_completeness(inventory)
        for path in list(inventory):
            with self.subTest(missing=path), self.assertRaises(ContractError) as caught:
                verify_pages_completeness({k: v for k, v in inventory.items() if k != path})
            self.assertEqual(caught.exception.code, "MISSING_MANIFESTED_FILE")
        verify_pages_completeness({k: v for k, v in inventory.items() if not k.startswith("pacman/")}, families=("apt", "rpm"))
        with self.assertRaises(ContractError) as caught:
            verify_pages_completeness({**inventory, "other/readme.txt": "a" * 64})
        self.assertEqual(caught.exception.code, "DISALLOWED_FILE")
        with self.assertRaises(ContractError):
            verify_pages_completeness(inventory, families=("zypper",))

    def test_install_docs_state_the_nonproduction_boundary_and_assemble(self):
        docs = render_install_docs()
        self.assertEqual(set(docs), {"docs/install/README.md", "docs/install/index.html", "docs/index.html", "docs/README.md", "rpm/rs9.repo"})
        for path, text in docs.items():
            if path != "rpm/rs9.repo":
                self.assertIn("NONPRODUCTION", text, path)
        self.assertIn("gpgcheck=1", docs["rpm/rs9.repo"])
        self.assertIn("repo_gpgcheck=1", docs["rpm/rs9.repo"])
        self.assertIn("gpgcheck=1\n", docs["rpm/rs9.repo"])
        self.assertIn("skip_if_unavailable=False\n", docs["rpm/rs9.repo"])
        self.assertIn(NONPRODUCTION_BANNER, docs["docs/index.html"])
        sources = collect_candidate_sources(files=dict(docs), cname=PAGES_HOST)
        self.assertEqual(sorted(sources), sorted([*docs, "CNAME"]))
        scratch = self.root / "assembled"
        scratch.mkdir()
        candidate = assemble_pages_candidate(scratch, files=dict(docs), cname=PAGES_HOST,
                                             exact_inventory=exact_inventory_for(sources))
        self.assertEqual(candidate.merkle["leaf_count"], 6)
        self.assertEqual(candidate.status()["merkle_root"], candidate.merkle["root"])
        self.assertEqual((scratch / "CNAME").read_bytes(), (PAGES_HOST + "\n").encode())

    def test_source_collection_still_rejects_collisions_and_foreign_cname(self):
        with self.assertRaises(ContractError) as collision:
            collect_candidate_sources(files={"CNAME": "x\n"}, cname=PAGES_HOST)
        self.assertEqual(collision.exception.code, "CANDIDATE_COLLISION")
        with self.assertRaises(ContractError) as foreign:
            collect_candidate_sources(cname="example.com")
        self.assertEqual(foreign.exception.code, "CANDIDATE_CNAME")
        with self.assertRaises(ContractError) as empty:
            collect_candidate_sources()
        self.assertEqual(empty.exception.code, "EMPTY_CANDIDATE")

    def test_write_custody_bundle_preserves_default_modes_under_both_umasks(self):
        for mask in (0o022, 0o077):
            old_umask = os.umask(mask)
            try:
                ancestor = self.root / f"ancestor_custody_{mask:o}"
                ancestor.mkdir(mode=0o700)
                os.chmod(ancestor, 0o700)
                target = ancestor / "bundle"
                target.mkdir(mode=0o700)
                os.chmod(target, 0o700)

                write_custody_bundle(
                    target,
                    family="deb",
                    system="amd64",
                    packages={"tf-cli_1.0-1_all.deb": b"sample-deb-content"},
                    authentication_sha256=self.AUTH,
                    source_commit=self.COMMIT,
                )

                self.assertEqual(ancestor.stat().st_mode & 0o777, 0o700, f"Ancestor chmoded under umask {oct(mask)}")
                self.assertEqual(target.stat().st_mode & 0o777, 0o700)
                self.assertEqual((target / "files").stat().st_mode & 0o777, 0o755 & ~mask)
                self.assertEqual((target / "files" / "tf-cli_1.0-1_all.deb").stat().st_mode & 0o777, 0o644 & ~mask)
                self.assertEqual((target / CUSTODY_MANIFEST).stat().st_mode & 0o777, 0o644 & ~mask)

                report = verify_public_tree_modes(target)
                self.assertEqual(report["status"], "fail")
            finally:
                os.umask(old_umask)



if __name__ == "__main__":
    unittest.main()
