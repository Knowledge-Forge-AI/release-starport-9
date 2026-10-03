"""Tests for public Pages tree scanner (rs9.pages)."""

import os
from pathlib import Path
import tempfile
import unittest

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


TRUTHFUL_PGP_PUBLIC_KEY = (
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


class PagesScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _create_clean_pages_tree(self) -> dict[str, str]:
        files = {
            "CNAME": "pkg.example.com\n",
            "index.html": "<!DOCTYPE html><html><body>Welcome</body></html>\n",
            "README.md": "# Public Repository\nDocumentation.\n",
            "keys/rs9.asc": TRUTHFUL_PGP_PUBLIC_KEY,
            "docs/guide.md": "# Documentation Guide\n",
            "docs/style.css": "body { font-family: sans-serif; }\n",
            "docs/install/index.html": "Installation",
            "docs/install/guide.txt": "Instructions",
            "apt/dists/stable/Release": "Origin: RS9\nLabel: RS9\nSuite: stable\n",
            "apt/dists/stable/Release.gpg": "FAKE-DETACHED-GPG-SIG",
            "apt/pool/main/m/my-app/my-app_1.0.0_amd64.deb": "FAKE-DEB-BYTES",
        }
        for rel_path, content in files.items():
            file_path = self.root / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, str):
                file_path.write_text(content)
            else:
                file_path.write_bytes(content)
        return files

    def test_clean_pages_tree_scan_succeeds(self):
        self._create_clean_pages_tree()
        manifest = scan_pages_tree(self.root)
        self.assertEqual(manifest["schema"], "rs9.pages-manifest.v1alpha1")
        self.assertEqual(manifest["file_count"], 11)
        self.assertIn("CNAME", manifest["files"])
        self.assertEqual(manifest["files"]["CNAME"]["category"], CATEGORY_CNAME)
        self.assertEqual(manifest["files"]["index.html"]["category"], CATEGORY_INDEX)
        self.assertEqual(manifest["files"]["keys/rs9.asc"]["category"], CATEGORY_PUBLIC_KEY)
        self.assertEqual(manifest["files"]["docs/guide.md"]["category"], CATEGORY_DOCS)
        self.assertEqual(
            manifest["files"]["apt/pool/main/m/my-app/my-app_1.0.0_amd64.deb"]["category"],
            CATEGORY_CANDIDATE_ASSET,
        )

    def test_path_classification(self):
        self.assertEqual(classify_pages_path("CNAME"), (True, CATEGORY_CNAME))
        self.assertEqual(classify_pages_path("index.html"), (True, CATEGORY_INDEX))
        self.assertEqual(classify_pages_path("docs/index.html"), (True, CATEGORY_INDEX))
        self.assertEqual(classify_pages_path("keys/rs9-archive-keyring.gpg"), (True, CATEGORY_PUBLIC_KEY))
        self.assertEqual(classify_pages_path("keys/rs9.asc"), (True, CATEGORY_PUBLIC_KEY))
        self.assertEqual(classify_pages_path("docs/style.css"), (True, CATEGORY_DOCS))
        self.assertEqual(classify_pages_path("apt/dists/stable/Release"), (True, CATEGORY_CANDIDATE_ASSET))
        self.assertEqual(classify_pages_path("apt/pool/main/pkg_1.0_amd64.deb"), (True, CATEGORY_CANDIDATE_ASSET))
        self.assertEqual(
            classify_pages_path("apt/dists/stable/by-hash/SHA256/" + "a" * 64),
            (True, CATEGORY_CANDIDATE_ASSET),
        )

        # Disallowed
        self.assertEqual(classify_pages_path("script.sh"), (False, ""))
        self.assertEqual(classify_pages_path("src/app.py"), (False, ""))
        self.assertEqual(classify_pages_path(".env"), (False, ""))
        self.assertEqual(classify_pages_path("id_rsa"), (False, ""))

    def test_private_key_content_rejected_fail_closed(self):
        self._create_clean_pages_tree()
        leak_file = self.root / "docs/key_leak.md"
        leak_file.write_text("-----" + "BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----\n")

        with self.assertRaises(ContractError) as ctx:
            scan_pages_tree(self.root)
        self.assertEqual(ctx.exception.code, "CREDENTIAL_DETECTED")

    def test_credential_token_content_rejected(self):
        self._create_clean_pages_tree()
        leak_file = self.root / "docs/api_notes.txt"
        leak_file.write_text("API token: ghp_" + "A" * 36 + "\n")

        with self.assertRaises(ContractError) as ctx:
            scan_pages_tree(self.root)
        self.assertEqual(ctx.exception.code, "CREDENTIAL_DETECTED")

    def test_sensitive_filenames_rejected(self):
        self._create_clean_pages_tree()
        bad_filenames = ["id_rsa", "id_ed25519", "private.key", "secret.token", "passwd.txt"]
        for bad_name in bad_filenames:
            with self.subTest(name=bad_name):
                bad_file = self.root / bad_name
                bad_file.write_text("sensitive")
                with self.assertRaises(ContractError) as ctx:
                    scan_pages_tree(self.root)
                self.assertIn(ctx.exception.code, ("PRIVATE_PAYLOAD_DETECTED", "DISALLOWED_FILE"))
                bad_file.unlink()

    def test_disallowed_file_types_rejected(self):
        self._create_clean_pages_tree()
        disallowed = ["backend.py", "deploy.sh", "database.sqlite", "config.yaml"]
        for name in disallowed:
            with self.subTest(name=name):
                f = self.root / name
                f.write_text("disallowed content")
                with self.assertRaises(ContractError) as ctx:
                    scan_pages_tree(self.root)
                self.assertEqual(ctx.exception.code, "DISALLOWED_FILE")
                f.unlink()

    def test_hidden_files_rejected(self):
        self._create_clean_pages_tree()
        hidden = self.root / ".env"
        hidden.write_text("SECRET=12345")
        with self.assertRaises(ContractError) as ctx:
            scan_pages_tree(self.root)
        self.assertEqual(ctx.exception.code, "DISALLOWED_FILE")

    def test_manifest_validation_and_unmanifested_file(self):
        self._create_clean_pages_tree()
        # Scan to get true manifest
        initial = scan_pages_tree(self.root)
        manifest_map = {path: info["sha256"] for path, info in initial["files"].items()}

        # Verify exact match succeeds
        validated = validate_pages_tree(self.root, manifest=manifest_map)
        self.assertEqual(validated["file_count"], len(manifest_map))

        # Add unmanifested file
        unmanifested = self.root / "docs/extra.md"
        unmanifested.write_text("# Extra file\n")
        with self.assertRaises(ContractError) as ctx:
            validate_pages_tree(self.root, manifest=manifest_map)
        self.assertEqual(ctx.exception.code, "UNMANIFESTED_FILE")
        unmanifested.unlink()

        # Missing manifested file
        (self.root / "CNAME").unlink()
        with self.assertRaises(ContractError) as ctx:
            validate_pages_tree(self.root, manifest=manifest_map)
        self.assertEqual(ctx.exception.code, "MISSING_MANIFESTED_FILE")

    def test_tamper_detected_against_manifest(self):
        self._create_clean_pages_tree()
        initial = scan_pages_tree(self.root)
        manifest_map = {path: info["sha256"] for path, info in initial["files"].items()}

        # Tamper a file
        (self.root / "index.html").write_text("<script>malicious();</script>")
        with self.assertRaises(ContractError) as ctx:
            validate_pages_tree(self.root, manifest=manifest_map)
        self.assertEqual(ctx.exception.code, "TAMPER_DETECTED")

    def test_symlink_rejected(self):
        self._create_clean_pages_tree()
        link = self.root / "symlink_file"
        target = self.root / "index.html"
        try:
            os.symlink(target, link)
        except OSError:
            self.skipTest("Symlinks not supported on this filesystem")

        with self.assertRaises(ContractError) as ctx:
            scan_pages_tree(self.root)
        self.assertEqual(ctx.exception.code, "SYMLINK_REJECTED")

    def test_pacman_and_rpm_artifacts_classified_and_scanned(self):
        test_paths = [
            ("pacman/x86_64/core.db", True, CATEGORY_CANDIDATE_ASSET),
            ("pacman/x86_64/core.files", True, CATEGORY_CANDIDATE_ASSET),
            ("pacman/x86_64/mypkg-1.0.0-1-x86_64.pkg.tar.zst", True, CATEGORY_CANDIDATE_ASSET),
            ("pacman/x86_64/mypkg-1.0.0-1-x86_64.pkg.tar.zst.sig", True, CATEGORY_CANDIDATE_ASSET),
            ("rpm/fedora/43/x86_64/Packages/app-1.0.0.rpm", True, CATEGORY_CANDIDATE_ASSET),
            ("rpm/fedora/43/x86_64/repodata/repomd.xml", True, CATEGORY_CANDIDATE_ASSET),
            ("rpm/fedora/43/x86_64/repodata/repomd.xml.asc", True, CATEGORY_CANDIDATE_ASSET),
            ("rpm/fedora/43/x86_64/repodata/filelists.xml.gz", True, CATEGORY_CANDIDATE_ASSET),
        ]
        for path, expected_allowed, expected_cat in test_paths:
            with self.subTest(path=path):
                allowed, cat = classify_pages_path(path)
                self.assertEqual(allowed, expected_allowed)
                self.assertEqual(cat, expected_cat)

        # Create tree with pacman and rpm artifacts
        (self.root / "rpm/fedora/43/x86_64/repodata").mkdir(parents=True, exist_ok=True)
        (self.root / "rpm/fedora/43/x86_64/repodata/repomd.xml").write_text("<repomd></repomd>\n")
        (self.root / "rpm/fedora/43/x86_64/repodata/repomd.xml.asc").write_text("-----BEGIN PGP SIGNATURE-----\nsig\n-----END PGP SIGNATURE-----\n")
        (self.root / "rpm/fedora/43/x86_64/Packages").mkdir(parents=True, exist_ok=True)
        (self.root / "rpm/fedora/43/x86_64/Packages/sample.rpm").write_bytes(b"\xed\xab\xee\xdbFAKE-RPM")
        (self.root / "pacman/x86_64").mkdir(parents=True, exist_ok=True)
        (self.root / "pacman/x86_64/repo.db").write_bytes(b"FAKE-ARCH-DB")
        (self.root / "pacman/x86_64/sample.pkg.tar.zst").write_bytes(b"FAKE-ZST-PKG")
        (self.root / "pacman/x86_64/sample.pkg.tar.zst.sig").write_bytes(b"FAKE-SIG")
        (self.root / "CNAME").write_text("mirror.example.com\n")

        scan = scan_pages_tree(self.root)
        self.assertFalse(scan["authoritative"])
        self.assertEqual(scan["file_count"], 7)

        # Manifested scan
        manifest = {p: info["sha256"] for p, info in scan["files"].items()}
        validated = validate_pages_tree(self.root, manifest=manifest)
        self.assertTrue(validated["authoritative"])
        self.assertEqual(validated["file_count"], 7)

    def test_candidate_validation_requires_manifest(self):
        self._create_clean_pages_tree()
        with self.assertRaises(ContractError) as ctx:
            validate_pages_tree(self.root, manifest=None)
        self.assertEqual(ctx.exception.code, "MANIFEST_REQUIRED")

    def test_binary_manifest_required_for_package_files(self):
        # Create an isolated package file in pool without any index
        pkg = self.root / "apt/pool/main/pkg.deb"
        pkg.parent.mkdir(parents=True, exist_ok=True)
        pkg.write_bytes(b"FAKE-DEB")
        with self.assertRaises(ContractError) as ctx:
            scan_pages_tree(self.root)
        self.assertEqual(ctx.exception.code, "MISSING_PACKAGE_INDEX")

    def test_sensitive_names_not_exempted_by_gpg_or_asc(self):
        self._create_clean_pages_tree()
        sensitive_cases = [
            "secret.gpg",
            "privkey.asc",
            "id_rsa.pub",
            "private.gpg",
            "credential.sig",
            "token.asc",
            "docs/secret.gpg",
            "assets/private.asc",
            "rpm/fedora/43/x86_64/repodata/secret.gpg",
        ]
        for bad_rel in sensitive_cases:
            with self.subTest(path=bad_rel):
                self.assertEqual(classify_pages_path(bad_rel), (False, ""))
                bad_file = self.root / bad_rel
                bad_file.parent.mkdir(parents=True, exist_ok=True)
                bad_file.write_bytes(b"sensitive-bytes")
                with self.assertRaises(ContractError) as ctx:
                    scan_pages_tree(self.root)
                self.assertIn(ctx.exception.code, ("PRIVATE_PAYLOAD_DETECTED", "DISALLOWED_FILE"))
                bad_file.unlink()

    def test_binary_secret_key_packets_rejected(self):
        self._create_clean_pages_tree()
        tag5_new = bytes([0xC0 | 5, 4, 1, 2, 3, 4])
        tag5_old = bytes([0x80 | (5 << 2) | 0x00, 4, 1, 2, 3, 4])
        tag7_new = bytes([0xC0 | 7, 4, 1, 2, 3, 4])
        mixed_keyring = bytes([0xC0 | 6, 2, 10, 20, 0xC0 | 7, 2, 30, 40])

        for payload in (tag5_new, tag5_old, tag7_new, mixed_keyring):
            with self.subTest(payload=payload.hex()):
                # Test in pubkey.gpg
                (self.root / "keys/rs9.asc").write_bytes(payload)
                with self.assertRaises(ContractError) as ctx:
                    scan_pages_tree(self.root)
                self.assertEqual(ctx.exception.code, "CREDENTIAL_DETECTED")
                (self.root / "keys/rs9.asc").write_text(TRUTHFUL_PGP_PUBLIC_KEY)

                # Test in candidate asset signature file
                (self.root / "apt/dists/stable/Release.gpg").write_bytes(payload)
                with self.assertRaises(ContractError) as ctx:
                    scan_pages_tree(self.root)
                self.assertEqual(ctx.exception.code, "CREDENTIAL_DETECTED")
                (self.root / "apt/dists/stable/Release.gpg").write_text("FAKE-DETACHED-GPG-SIG")

    def test_ascii_armor_secret_key_and_smuggled_packets_rejected(self):
        self._create_clean_pages_tree()
        import base64
        secret_armor = (
            "-----BEGIN PGP SECRET KEY BLOCK-----\n"
            "Version: Test\n\n"
            "fake-secret-key-material\n"
            "-----END PGP SECRET KEY BLOCK-----\n"
        )
        (self.root / "keys/rs9.asc").write_text(secret_armor)
        with self.assertRaises(ContractError) as ctx:
            scan_pages_tree(self.root)
        self.assertEqual(ctx.exception.code, "CREDENTIAL_DETECTED")

        tag5_bytes = bytes([0xC0 | 5, 4, 1, 2, 3, 4])
        smuggled_b64 = base64.b64encode(tag5_bytes).decode("ascii")
        smuggled_armor = (
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
            "Version: RS9\n\n"
            f"{smuggled_b64}\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        (self.root / "keys/rs9.asc").write_text(smuggled_armor)
        with self.assertRaises(ContractError) as ctx:
            scan_pages_tree(self.root)
        self.assertEqual(ctx.exception.code, "CREDENTIAL_DETECTED")

    def test_invalid_public_key_material_rejected(self):
        self._create_clean_pages_tree()
        (self.root / "keys/rs9.asc").write_text("NOT-AN-OPENPGP-KEY")
        with self.assertRaises(ContractError) as ctx:
            scan_pages_tree(self.root)
        self.assertEqual(ctx.exception.code, "INVALID_PUBLIC_KEY")

    def test_public_key_cannot_hide_a_secret_packet_after_invalid_trailer(self):
        self._create_clean_pages_tree()
        public_packet = bytes([0xC6, 2, 10, 20])
        secret_packet = bytes([0xC5, 2, 30, 40])
        for payload in (public_packet + b"invalid" + secret_packet,
                        public_packet + bytes([0xC6, 10, 1])):
            (self.root / "keys/rs9.asc").write_bytes(payload)
            with self.assertRaises(ContractError) as caught:
                scan_pages_tree(self.root)
            self.assertEqual(caught.exception.code, "INVALID_PUBLIC_KEY")

        import base64
        tag13_only = bytes([0xC0 | 13, 4, ord('t'), ord('e'), ord('s'), ord('t')])
        tag13_armor = (
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
            "Version: RS9\n\n"
            f"{base64.b64encode(tag13_only).decode('ascii')}\n"
            "-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        (self.root / "keys/rs9.asc").write_text(tag13_armor)
        with self.assertRaises(ContractError) as ctx:
            scan_pages_tree(self.root)
        self.assertEqual(ctx.exception.code, "INVALID_PUBLIC_KEY")

    def test_broad_suffix_allowlist_bypass_rejected(self):
        self._create_clean_pages_tree()
        disallowed_paths = [
            "random/unreviewed.db",
            "other/package.tar.gz",
            "somewhere/bad.sig",
            "nested/foo/key.asc",
            "sub/dir/pubkey.gpg",
            "unauthorized/file.deb",
            "dir/test.gz",
            "deep/path/archive.tar.xz",
            "unreviewed.db",
            "random.tar.gz",
            "leak.sig",
        ]
        for path in disallowed_paths:
            with self.subTest(path=path):
                self.assertEqual(classify_pages_path(path), (False, ""))
                f = self.root / path
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_bytes(b"disallowed-bytes")
                with self.assertRaises(ContractError) as ctx:
                    scan_pages_tree(self.root)
                self.assertEqual(ctx.exception.code, "DISALLOWED_FILE")
                f.unlink()


if __name__ == "__main__":
    unittest.main()
