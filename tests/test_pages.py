"""Tests for public Pages tree scanner (rs9.pages)."""

import hashlib
import io
import lzma
import os
from pathlib import Path
import stat
import struct
import subprocess
import tarfile
import sys
import tempfile
import unittest
import warnings
import gc
from unittest.mock import MagicMock, patch

from rs9.errors import ContractError
from rs9.pages import (
    CATEGORY_CANDIDATE_ASSET,
    CATEGORY_CNAME,
    CATEGORY_DOCS,
    CATEGORY_INDEX,
    CATEGORY_PUBLIC_KEY,
    MERKLE_ALGORITHM,
    _zstd_decode,
    _zstd_frames_valid,
    check_no_secret_key_packets,
    classify_pages_path,
    clean_openpgp_framing,
    detect_binary_format,
    merkle_inventory,
    scan_binary_artifact,
    scan_pages_tree,
    validate_pages_tree,
    verify_merkle_inventory,
)
from rs9.security import scan_bytes_for_credentials, validate_nonproduction_key_path
from tests.test_repo_apt import build_minimal_deb

# Spelled in pieces so this source never contains a literal private key block.
PRIVATE_BLOCK = "-----" + "BEGIN PGP PRIVATE KEY BLOCK-----\nfixture-only-material\n-----END PGP PRIVATE KEY BLOCK-----\n"
SECRET_PACKET = bytes([0xC0 | 5, 4, 1, 2, 3, 4])


def cpio_newc(files: dict[str, bytes]) -> bytes:
    def entry(name: str, data: bytes, mode: int, ino: int) -> bytes:
        raw_name = name.encode() + b"\0"
        fields = (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(raw_name), 0)
        header = b"070701" + b"".join(b"%08X" % value for value in fields) + raw_name
        return header + b"\0" * (-len(header) % 4) + data + b"\0" * (-len(data) % 4)

    out = b"".join(entry(name, data, 0o100644, i) for i, (name, data) in enumerate(files.items(), 1))
    return out + entry("TRAILER!!!", b"", 0, 0)


def rpm_header(store: bytes, magic: bytes = b"\x8e\xad\xe8\x01") -> bytes:
    entry = struct.pack(">IIII", 1000, 7, 0, len(store))
    return magic + b"\0\0\0\0" + struct.pack(">II", 1, len(store)) + entry + store


def make_rpm(files: dict[str, bytes], *, signature_store: bytes = b"sig\0", compress: bool = True) -> bytes:
    lead = (b"\xed\xab\xee\xdb" + b"\x03\x00" + struct.pack(">HH", 0, 1) + b"theme-forge".ljust(66, b"\0")
            + struct.pack(">HH", 1, 5) + b"\0" * 16)
    signature = rpm_header(signature_store)
    signature += b"\0" * (-len(signature) % 8)
    header = rpm_header(b"theme-forge\0")
    payload = cpio_newc(files)
    return lead + signature + header + (lzma.compress(payload, check=lzma.CHECK_CRC32) if compress else payload)


def make_xz_deb(payload_name: str, payload: bytes) -> bytes:
    def tar_xz(name: str, data: bytes) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:xz") as archive:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    control = b"Package: sample\nVersion: 1.0\nArchitecture: amd64\nDescription: sample\n"
    members = [("debian-binary", b"2.0\n"), ("control.tar.xz", tar_xz("./control", control)),
               ("data.tar.xz", tar_xz(payload_name, payload))]
    out = b"!<arch>\n"
    for name, data in members:
        out += f"{name:<16}0           0     0     100644  {len(data):<10}`\n".encode() + data
        out += b"\n" if len(data) % 2 else b""
    return out


def zstd_raw_frame(content: bytes) -> bytes:
    """Minimal valid frame: single segment, one raw last block (no decoder needed to build it)."""
    return (b"\x28\xb5\x2f\xfd" + b"\x20" + bytes([len(content)])
            + ((len(content) << 3) | 1).to_bytes(3, "little") + content)


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


class FormatAwareBinaryScanTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        self.temp_dir.cleanup()

    def place(self, rel: str, data: bytes) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def test_format_detection_is_by_magic_only(self):
        self.assertEqual(detect_binary_format(b"\xed\xab\xee\xdb" + b"x" * 8), "rpm")
        self.assertEqual(detect_binary_format(b"!<arch>\nrest"), "ar")
        self.assertEqual(detect_binary_format(b"\xfd7zXZ\x00rest"), "xz")
        self.assertEqual(detect_binary_format(b"\x28\xb5\x2f\xfdrest"), "zstd")
        self.assertEqual(detect_binary_format(b"\x1f\x8brest"), "gzip")
        self.assertEqual(detect_binary_format(b"070701" + b"0" * 20), "cpio")
        self.assertEqual(detect_binary_format(b"x" * 257 + b"ustar" + b"\0" * 10), "tar")
        self.assertIsNone(detect_binary_format(b"plain text"))

    def test_real_rpm_with_header_bytes_that_parse_as_a_secret_packet_is_not_a_false_positive(self):
        # Offset 173 holds a tag-5 packet header: the raw prefix scan (0xed lead byte, 171 byte
        # "packet") reads it as a secret key, though these are plain RPM signature header bytes.
        rpm = make_rpm({"usr/bin/tool": b"#!/bin/sh\n"}, signature_store=b"\0" * 45 + b"\xc5\x01\x00" + b"\0" * 8)
        with self.assertRaises(ContractError) as legacy:
            check_no_secret_key_packets(rpm)
        self.assertEqual(legacy.exception.code, "CREDENTIAL_DETECTED")
        evidence = scan_binary_artifact(rpm, "x.rpm")
        self.assertEqual(evidence["format"], "rpm")
        self.assertTrue(evidence["complete"])
        self.assertEqual(evidence["members_scanned"], 1)
        self.assertIn("xz", evidence["formats_seen"])
        self.place("rpm/fedora/43/x86_64/Packages/tool.rpm", rpm)
        self.place("rpm/fedora/43/x86_64/repodata/repomd.xml", b"<repomd/>\n")
        files = scan_pages_tree(self.root)["files"]
        self.assertEqual(files["rpm/fedora/43/x86_64/Packages/tool.rpm"]["format_scan"]["format"], "rpm")

    def test_real_xz_stream_that_parses_as_a_secret_packet_is_not_a_false_positive(self):
        stream = None
        for i in range(20000):
            body = b"".join(hashlib.sha256(f"{i}-{j}".encode()).digest() for j in range(3))
            candidate = lzma.compress(body, check=lzma.CHECK_CRC32)
            if len(candidate) > 58 and candidate[57] == 0xC5:
                stream = candidate
                break
        self.assertIsNotNone(stream, "no deterministic xz sample found")
        with self.assertRaises(ContractError):
            check_no_secret_key_packets(stream)
        self.place("apt/dists/resolute/main/binary-amd64/Packages.xz", stream)
        record = scan_pages_tree(self.root)["files"]["apt/dists/resolute/main/binary-amd64/Packages.xz"]
        self.assertEqual(record["format_scan"]["format"], "xz")
        self.assertTrue(record["format_scan"]["complete"])

    def test_secret_material_inside_rpm_payload_is_rejected(self):
        for name, content in (("etc/server.conf", PRIVATE_BLOCK.encode()),
                              ("usr/share/keyrings/vendor.gpg", SECRET_PACKET),
                              ("usr/share/data.bin", SECRET_PACKET)):
            with self.subTest(member=name), self.assertRaises(ContractError) as caught:
                scan_binary_artifact(make_rpm({name: content}), "x.rpm")
            self.assertEqual(caught.exception.code, "CREDENTIAL_DETECTED")
        token = ("ghp_" + "A" * 36).encode()
        with self.assertRaises(ContractError):
            scan_binary_artifact(make_rpm({"etc/notes.txt": token}), "x.rpm")

    def test_secret_material_inside_deb_members_is_rejected_for_every_compression(self):
        for payload_name, content in (("./etc/secret.conf", PRIVATE_BLOCK.encode()), ("./etc/k.pgp", SECRET_PACKET)):
            for deb in (build_minimal_deb("sample", "1.0", "amd64", payload_content=content),
                        make_xz_deb(payload_name, content)):
                with self.subTest(payload=payload_name), self.assertRaises(ContractError) as caught:
                    scan_binary_artifact(deb, "sample.deb")
                self.assertEqual(caught.exception.code, "CREDENTIAL_DETECTED")
        clean = make_xz_deb("./usr/bin/tool", b"#!/bin/sh\n")
        evidence = scan_binary_artifact(clean, "sample.deb")
        self.assertEqual((evidence["format"], evidence["complete"]), ("ar", True))
        self.assertTrue({"ar", "xz", "tar"} <= set(evidence["formats_seen"]))

    def test_secret_material_inside_plain_tar_and_gzip_is_rejected(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            info = tarfile.TarInfo("pkg/id.asc")
            info.size = len(PRIVATE_BLOCK)
            archive.addfile(info, io.BytesIO(PRIVATE_BLOCK.encode()))
        with self.assertRaises(ContractError) as caught:
            scan_binary_artifact(buffer.getvalue(), "x.tar.gz")
        self.assertEqual(caught.exception.code, "CREDENTIAL_DETECTED")

    def test_unproven_or_malformed_containers_fall_back_to_the_raw_scan(self):
        for blob in (b"\xed\xab\xee\xdbFAKE-RPM", b"!<arch>\nnot an archive", b"\xfd7zXZ\x00corrupt",
                     b"\x28\xb5\x2f\xfdnot-a-frame", b"\x1f\x8bnot-gzip", b"plain"):
            with self.subTest(blob=blob):
                self.assertIsNone(scan_binary_artifact(blob, "x.bin"))
        # The legacy raw scan keeps catching a secret packet that merely claims a suffix.
        self.place("rpm/fedora/43/x86_64/Packages/fake.rpm", bytes([0xC5, 1, 0]))
        with self.assertRaises(ContractError) as caught:
            scan_pages_tree(self.root)
        self.assertEqual(caught.exception.code, "CREDENTIAL_DETECTED")

    def test_rpm_with_undecodable_payload_is_structurally_proven_but_incomplete(self):
        rpm = make_rpm({"usr/bin/tool": b"x"})
        header_end = len(rpm) - len(lzma.compress(cpio_newc({"usr/bin/tool": b"x"}), check=lzma.CHECK_CRC32))
        broken = rpm[:header_end] + b"\x28\xb5\x2f\xfd-not-a-valid-frame"
        evidence = scan_binary_artifact(broken, "x.rpm")
        self.assertEqual(evidence["format"], "rpm")
        self.assertFalse(evidence["complete"])
        self.assertIn("rpm-payload", evidence["unscanned_streams"])

    def test_zstd_frame_walker_and_scan_evidence(self):
        frame = zstd_raw_frame(b"public bytes only")
        self.assertTrue(_zstd_frames_valid(frame))
        self.assertTrue(_zstd_frames_valid(frame + frame))
        self.assertTrue(_zstd_frames_valid(b"\x50\x2a\x4d\x18" + (3).to_bytes(4, "little") + b"abc" + frame))
        reserved_block = frame[:6] + (((len(b"public bytes only") << 3) | 1) | (3 << 1)).to_bytes(3, "little") + frame[9:]
        for bad in (frame[:-1], frame + b"x", b"", b"\x28\xb5\x2f\xfd", reserved_block):
            with self.subTest(bad=bad):
                self.assertFalse(_zstd_frames_valid(bad))
        evidence = scan_binary_artifact(frame, "pkg.pkg.tar.zst")
        self.assertEqual(evidence["format"], "zstd")
        # Without a reviewed decoder the stream is flagged instead of silently treated as scanned.
        self.assertEqual(evidence["complete"], not evidence["unscanned_streams"])

    def test_zstd_decode_resource_management_normal_and_limit(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            script = Path(tmp_dir) / "zstd"
            script.write_text(
                f"#!{sys.executable}\n"
                "import sys\n"
                "raw = sys.stdin.buffer.read(16)\n"
                "if b'overflow' in raw:\n"
                "    sys.stdout.buffer.write(b'X' * 50000)\n"
                "else:\n"
                "    sys.stdout.buffer.write(b'decoded-payload')\n"
            )
            script.chmod(0o755)

            with patch("shutil.which", return_value=str(script)), \
                 patch("importlib.import_module", side_effect=ImportError("No native zstd")):

                # Normal decode: within limit, context management closes resources without ResourceWarning
                with warnings.catch_warnings(record=True) as recorded:
                    warnings.simplefilter("always", ResourceWarning)
                    decoded = _zstd_decode(b"normal-data", limit=1000)
                    self.assertEqual(decoded, b"decoded-payload")
                    gc.collect()
                    resource_warnings = [w for w in recorded if issubclass(w.category, ResourceWarning)]
                    self.assertEqual(resource_warnings, [])

                # Limit exceeded: feeder owns stdin, broken pipe handled, feeder joined before exit, kill on limit
                with warnings.catch_warnings(record=True) as recorded:
                    warnings.simplefilter("always", ResourceWarning)
                    with self.assertRaises(ContractError) as caught:
                        _zstd_decode(b"overflow-data" + b"X" * (2 * 1024 ** 2), limit=100)
                    self.assertEqual(caught.exception.code, "PAGES_LIMIT")
                    gc.collect()
                    resource_warnings = [w for w in recorded if issubclass(w.category, ResourceWarning)]
                    self.assertEqual(resource_warnings, [])

    def test_zstd_decoder_that_closes_stdout_then_hangs_is_killed_and_reaped(self):
        real_popen = subprocess.Popen
        children = []
        def spawn(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            real_wait = child.wait
            def bounded_wait(timeout=None):
                return real_wait(timeout=0.1 if timeout is not None else None)
            child.wait = bounded_wait
            children.append(child)
            return child
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "zstd"
            script.write_text(f"#!{sys.executable}\nimport os, sys, time\n"
                              "os.close(1)\nsys.stdin.buffer.read()\ntime.sleep(60)\n")
            script.chmod(0o755)
            with patch("rs9.pages.shutil.which", return_value=str(script)), \
                 patch("rs9.pages.subprocess.Popen", side_effect=spawn), \
                 patch("rs9.pages.importlib.import_module", side_effect=ImportError), \
                 warnings.catch_warnings(record=True) as recorded:
                warnings.simplefilter("always", ResourceWarning)
                self.assertIsNone(_zstd_decode(b"input", limit=1000))
                self.assertEqual(len(children), 1)
                self.assertLess(children[0].returncode, 0)
                self.assertTrue(children[0].stdin.closed)
                self.assertTrue(children[0].stdout.closed)
                gc.collect()
                self.assertEqual([w for w in recorded if issubclass(w.category, ResourceWarning)], [])

    def test_clean_openpgp_framing_requires_exact_packet_sequence(self):
        self.assertEqual(clean_openpgp_framing(SECRET_PACKET), [5])
        self.assertEqual(clean_openpgp_framing(bytes([0xC6, 2, 10, 20]) + SECRET_PACKET), [6, 5])
        for data in (SECRET_PACKET + b"x", SECRET_PACKET[:-1], b"\x7fELF" + b"\0" * 20, b"", b"\xc5\x01",
                     bytes([0xC0 | 5, 0xE0, 1, 2])):
            with self.subTest(data=data):
                self.assertIsNone(clean_openpgp_framing(data))

    def test_decoded_byte_budget_is_enforced(self):
        import rs9.pages as pages

        original = pages.MAX_SCAN_DECODED_BYTES
        pages.MAX_SCAN_DECODED_BYTES = 1024
        try:
            with self.assertRaises(ContractError) as caught:
                scan_binary_artifact(lzma.compress(b"\0" * 100_000), "x.xz")
        finally:
            pages.MAX_SCAN_DECODED_BYTES = original
        self.assertEqual(caught.exception.code, "PAGES_LIMIT")


class ByteScanAndKeyPathTests(unittest.TestCase):
    def test_private_key_armor_is_rejected_in_any_byte_stream(self):
        for armor in ("-----" + "BEGIN PRIVATE KEY-----", "-----" + "BEGIN RSA PRIVATE KEY-----",
                      "-----" + "BEGIN OPENSSH PRIVATE KEY-----", "-----" + "BEGIN PGP PRIVATE KEY BLOCK-----",
                      "-----" + "BEGIN PGP SECRET KEY BLOCK-----"):
            for data in (armor.encode(), b"\x00\x01" + armor.encode() + b"\x00"):
                with self.subTest(armor=armor), self.assertRaises(ContractError) as caught:
                    scan_bytes_for_credentials(data)
                self.assertEqual(caught.exception.code, "CREDENTIAL_DETECTED")
        scan_bytes_for_credentials(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n")

    def test_vendor_tokens_are_text_gated_and_generic_bearer_strings_are_not_secrets(self):
        token = ("ghp_" + "A" * 36).encode()
        with self.assertRaises(ContractError):
            scan_bytes_for_credentials(b"token=" + token)
        scan_bytes_for_credentials(b"\x00\x01compiled constant " + token)  # binary: not text-scanned by default
        with self.assertRaises(ContractError):
            scan_bytes_for_credentials(b"\x00\x01 header " + token, token_scan=True)
        scan_bytes_for_credentials(b"Send Authorization: Bearer " + b"a" * 40 + b" in the header")

    def test_fixture_key_paths_must_be_explicitly_nonproduction(self):
        for good in ("/etc/apt/keyrings/rs9-nonproduction.gpg", "etc/rs9/non-production/key.asc",
                     "keys/rs9_nonproduction.asc"):
            validate_nonproduction_key_path(good)
        for bad in ("/etc/apt/keyrings/rs9.gpg", "/usr/share/keyrings/production/rs9-nonproduction.gpg",
                    "keys/live/nonproduction.asc", "keys/rs9-archive-keyring.gpg", "../escape-nonproduction.gpg", ""):
            with self.subTest(path=bad), self.assertRaises(ContractError):
                validate_nonproduction_key_path(bad)
        with self.assertRaises(ContractError):
            validate_nonproduction_key_path(None)


class MerkleInventoryTests(unittest.TestCase):
    INVENTORY = {"CNAME": "a" * 64, "apt/dists/resolute/Release": "b" * 64, "keys/rs9.asc": "c" * 64}

    def test_single_file_root_is_the_domain_separated_leaf(self):
        doc = merkle_inventory({"CNAME": "a" * 64})
        leaf = hashlib.sha256(b"\x00" + (5).to_bytes(4, "big") + b"CNAME" + bytes.fromhex("a" * 64)).hexdigest()
        self.assertEqual((doc["algorithm"], doc["leaf_count"], doc["root"]), (MERKLE_ALGORITHM, 1, leaf))

    def test_root_is_deterministic_order_independent_and_exact(self):
        doc = merkle_inventory(self.INVENTORY)
        self.assertEqual(doc, merkle_inventory(dict(reversed(list(self.INVENTORY.items())))))
        self.assertEqual([row["path"] for row in doc["leaves"]], sorted(self.INVENTORY))
        leaves = [bytes.fromhex(row["leaf"]) for row in doc["leaves"]]
        left = hashlib.sha256(b"\x01" + leaves[0] + leaves[1]).digest()
        # Odd node is promoted, not duplicated.
        self.assertEqual(doc["root"], hashlib.sha256(b"\x01" + left + leaves[2]).hexdigest())
        roots = {merkle_inventory({**self.INVENTORY, "CNAME": "d" * 64})["root"],
                 merkle_inventory({**self.INVENTORY, "CNAME2": self.INVENTORY["CNAME"]})["root"],
                 merkle_inventory({k: v for k, v in self.INVENTORY.items() if k != "CNAME"})["root"],
                 doc["root"]}
        self.assertEqual(len(roots), 4)

    def test_inventory_is_validated_and_verification_fails_closed(self):
        for bad in ({}, {"/abs": "a" * 64}, {"a/../b": "a" * 64}, {"x": "short"}):
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                merkle_inventory(bad)
        doc = merkle_inventory(self.INVENTORY)
        verify_merkle_inventory(doc, self.INVENTORY)
        for wrong in ({**self.INVENTORY, "extra": "e" * 64}, {**self.INVENTORY, "CNAME": "0" * 64}):
            with self.subTest(wrong=wrong), self.assertRaises(ContractError) as caught:
                verify_merkle_inventory(doc, wrong)
            self.assertEqual(caught.exception.code, "MERKLE_MISMATCH")
        for bad_doc in (None, {}, {**doc, "root": "0" * 64}, {**doc, "algorithm": "other"}):
            with self.subTest(doc=bad_doc), self.assertRaises(ContractError):
                verify_merkle_inventory(bad_doc, self.INVENTORY)


class PagesMetadataAndSignerContractTests(unittest.TestCase):
    def test_pages_metadata_signature_verified_before_assembly(self):
        from rs9.rpm_repository import sign_metadata, prepare_public_directory
        from tests.test_repo_apt import FixtureSigner
        from rs9.build_native import CommandReceipt

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            arch_dir = root / "rpm" / "fedora/43" / "x86_64"
            prepare_public_directory(arch_dir / "Packages", root / "rpm")
            repodata = arch_dir / "repodata"
            repodata.mkdir(mode=0o755)
            os.chmod(repodata, 0o755)
            repomd = repodata / "repomd.xml"
            from tests.rpm_metadata_fixtures import create_valid_repodata
            create_valid_repodata(arch_dir, [])
            os.chmod(repomd, 0o644)

            signer = FixtureSigner()
            receipt = CommandReceipt(["createrepo_c", str(arch_dir)], 0, b"index created\n", b"")
            report = sign_metadata(signer, arch_dir, receipt=receipt)

            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["operation"], "repository-metadata")
            self.assertEqual(report["verified_issuer"], signer.primary_fingerprint)
            sig_file = repodata / "repomd.xml.asc"
            self.assertTrue(sig_file.is_file())
            self.assertEqual(stat.S_IMODE(sig_file.stat().st_mode), 0o644)

            # Verification of signature on disk
            verified = signer.verify(repomd.read_bytes(), sig_file.read_bytes())
            self.assertEqual(verified["verified_issuer"], signer.primary_fingerprint)

    def test_pages_signer_contract_no_root_writer(self):
        from rs9.hosted_deb import ContainerRunner, _user

        with patch("rs9.hosted_deb.os.getuid", return_value=1001), patch("rs9.hosted_deb.os.getgid", return_value=1002):
            user_val = _user()
            self.assertEqual(user_val, "1001:1002")
            runner = ContainerRunner(None, "fedora:43", platform="linux/amd64", user=user_val)
            argv = runner.docker_argv(["rpmsign", "pkg.rpm"])
            self.assertIn("--user", argv)
            self.assertIn("1001:1002", argv)
            self.assertIn("HOME=/tmp", argv)

    def test_pages_metadata_verification_failure_raises_contract_error_with_receipt_hashes(self):
        from rs9.rpm_repository import sign_metadata
        from tests.test_repo_apt import FixtureSigner
        from rs9.build_native import CommandReceipt

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            repodata = root / "repodata"
            repodata.mkdir(mode=0o755)
            repomd = repodata / "repomd.xml"
            from tests.rpm_metadata_fixtures import create_valid_repodata
            create_valid_repodata(root, [])
            os.chmod(repomd, 0o644)

            signer = FixtureSigner(fingerprint="A" * 40)
            tamper_signer = MagicMock()
            tamper_signer.detach_sign.return_value = b"corrupted-signature"
            tamper_signer.verify.side_effect = ContractError("VERIFICATION_FAILED", "Bad signature")

            receipt = CommandReceipt(["createrepo_c", str(root)], 0, b"out", b"err")
            with self.assertRaises(ContractError) as caught:
                sign_metadata(tamper_signer, root, receipt=receipt)

            self.assertEqual(caught.exception.code, "RPM_REPOSITORY_OPERATION")
            details = caught.exception.details
            self.assertEqual(details["substage"], "signature-verify")
            self.assertEqual(details["causal_code"], "VERIFICATION_FAILED")
            self.assertEqual(details["stdout_sha256"], receipt.stdout_sha256)
            self.assertEqual(details["stderr_sha256"], receipt.stderr_sha256)


if __name__ == "__main__":
    unittest.main()
