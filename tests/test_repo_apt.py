"""Tests for deterministic APT repository index and candidate generator (rs9.repo_apt)."""

import gzip
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.pages import scan_pages_tree
from rs9.repo_apt import (
    AptRepositoryCandidate,
    DebPackage,
    build_apt_repository,
    parse_deb_control,
    validate_apt_repository,
)
from rs9.signed_store import SignedStore


def build_minimal_deb(
    package: str,
    version: str,
    architecture: str,
    description: str = "A sample debian package",
    maintainer: str = "Maintainer <pkg@example.com>",
    depends: str | None = None,
    payload_content: bytes = b"binary payload\n",
    *,
    custom_control: bytes | None = None,
    symlink_in_control: bool = False,
    duplicate_control: bool = False,
    installed_size: int | None = None,
) -> bytes:
    """Build a deterministic .deb archive for testing."""
    debian_binary = b"2.0\n"

    if custom_control is not None:
        control_text = custom_control
    else:
        control_lines = [
            f"Package: {package}",
            f"Version: {version}",
            f"Architecture: {architecture}",
            f"Maintainer: {maintainer}",
            f"Description: {description}",
        ]
        if installed_size is not None:
            control_lines.append(f"Installed-Size: {installed_size}")
        if depends:
            control_lines.append(f"Depends: {depends}")
        control_text = ("\n".join(control_lines) + "\n").encode("utf-8")

    control_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=control_buf, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            ti = tarfile.TarInfo(name="./control")
            ti.size = len(control_text)
            ti.mtime = 0
            ti.mode = 0o644
            tar.addfile(ti, io.BytesIO(control_text))

            if duplicate_control:
                ti2 = tarfile.TarInfo(name="control")
                ti2.size = len(control_text)
                ti2.mtime = 0
                ti2.mode = 0o644
                tar.addfile(ti2, io.BytesIO(control_text))

            if symlink_in_control:
                ti_sym = tarfile.TarInfo(name="./evil_symlink")
                ti_sym.type = tarfile.SYMTYPE
                ti_sym.linkname = "/etc/passwd"
                ti_sym.mtime = 0
                tar.addfile(ti_sym)

    control_tar_gz = control_buf.getvalue()

    data_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=data_buf, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            ti = tarfile.TarInfo(name=f"./usr/bin/{package}")
            ti.size = len(payload_content)
            ti.mtime = 0
            ti.mode = 0o755
            tar.addfile(ti, io.BytesIO(payload_content))
    data_tar_gz = data_buf.getvalue()

    def make_ar_header(name: str, size: int) -> bytes:
        name_field = f"{name}/".ljust(16)[:16].encode("ascii")
        mtime_field = "0".ljust(12)[:12].encode("ascii")
        owner_field = "0".ljust(6)[:6].encode("ascii")
        group_field = "0".ljust(6)[:6].encode("ascii")
        mode_field = "100644".ljust(8)[:8].encode("ascii")
        size_field = str(size).ljust(10)[:10].encode("ascii")
        magic = b"\x60\n"
        return name_field + mtime_field + owner_field + group_field + mode_field + size_field + magic

    out = io.BytesIO()
    out.write(b"!<arch>\n")
    for name, content in [
        ("debian-binary", debian_binary),
        ("control.tar.gz", control_tar_gz),
        ("data.tar.gz", data_tar_gz),
    ]:
        out.write(make_ar_header(name, len(content)))
        out.write(content)
        if len(content) % 2 == 1:
            out.write(b"\n")

    return out.getvalue()


class RepoAptTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

        self.deb_amd64 = build_minimal_deb(
            package="hello-world",
            version="1.0.0",
            architecture="amd64",
            description="Hello World package for amd64",
            payload_content=b"ELF-SIMULATED-AMD64-PAYLOAD",
        )
        self.deb_arm64 = build_minimal_deb(
            package="hello-world",
            version="1.0.0",
            architecture="arm64",
            description="Hello World package for arm64",
            payload_content=b"ELF-SIMULATED-ARM64-PAYLOAD",
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_deb_parsing_and_metadata(self):
        control_amd64 = parse_deb_control(self.deb_amd64)
        self.assertEqual(control_amd64["Package"], "hello-world")
        self.assertEqual(control_amd64["Version"], "1.0.0")
        self.assertEqual(control_amd64["Architecture"], "amd64")

        control_arm64 = parse_deb_control(self.deb_arm64)
        self.assertEqual(control_arm64["Architecture"], "arm64")

    def test_control_duplicates_malformed_ar_and_release_injection_rejected(self):
        bad=build_minimal_deb("hello-world","1.0.0","amd64",custom_control=b"Package: hello-world\nPackage: other\nVersion: 1.0.0\nArchitecture: amd64\n")
        with self.assertRaises(ContractError):parse_deb_control(bad)
        changed=bytearray(self.deb_amd64);changed[66:68]=b"xx"
        with self.assertRaises(ContractError):parse_deb_control(bytes(changed))
        with self.assertRaises(ContractError):parse_deb_control(self.deb_amd64+b"trailing")
        with self.assertRaises(ContractError):AptRepositoryCandidate(self.root/"bad",distribution="../../escape")
        with self.assertRaises(ContractError):AptRepositoryCandidate(self.root/"bad",origin="safe\nOrigin: unsafe")
        repo=AptRepositoryCandidate(self.root/"candidate")
        with self.assertRaises(ContractError):repo.build_indices(release_date="today\nSHA256: false")

    def test_deterministic_repository_generation(self):
        repo_a = build_apt_repository(
            self.root / "repo_a",
            packages_bytes=[self.deb_amd64, self.deb_arm64],
            release_date="Thu, 01 Jan 2026 00:00:00 +0000",
        )
        repo_b = build_apt_repository(
            self.root / "repo_b",
            packages_bytes=[self.deb_amd64, self.deb_arm64],
            release_date="Thu, 01 Jan 2026 00:00:00 +0000",
        )

        dir_a = self.root / "repo_a/dists/resolute"
        dir_b = self.root / "repo_b/dists/resolute"

        self.assertEqual((dir_a / "Release").read_bytes(), (dir_b / "Release").read_bytes())

        for name in ("Packages", "Packages.gz", "Packages.xz"):
            file_a = dir_a / f"main/binary-amd64/{name}"
            file_b = dir_b / f"main/binary-amd64/{name}"
            self.assertEqual(file_a.read_bytes(), file_b.read_bytes())

        for name in ("Packages", "Packages.gz", "Packages.xz"):
            file_a = dir_a / f"main/binary-arm64/{name}"
            file_b = dir_b / f"main/binary-arm64/{name}"
            self.assertEqual(file_a.read_bytes(), file_b.read_bytes())

    def test_repository_structure_and_by_hash(self):
        repo_root = self.root / "repo"
        build_apt_repository(
            repo_root,
            packages_bytes=[self.deb_amd64, self.deb_arm64],
        )

        val = validate_apt_repository(repo_root)
        self.assertEqual(val["distribution"], "resolute")
        self.assertEqual(val["verified_indices"], 6)
        self.assertFalse(val["signature_authenticated"])
        self.assertFalse(val["confers_signature_authentication"])

        dist_dir = repo_root / "dists/resolute"
        release_bytes = (dist_dir / "Release").read_bytes()
        import hashlib

        rel_sha = hashlib.sha256(release_bytes).hexdigest()
        by_hash_rel = dist_dir / f"by-hash/SHA256/{rel_sha}"
        self.assertTrue(by_hash_rel.exists())
        self.assertEqual(by_hash_rel.read_bytes(), release_bytes)

        pkg_amd64 = dist_dir / "main/binary-amd64/Packages"
        pkg_sha = hashlib.sha256(pkg_amd64.read_bytes()).hexdigest()
        by_hash_pkg = dist_dir / f"main/binary-amd64/by-hash/SHA256/{pkg_sha}"
        self.assertTrue(by_hash_pkg.exists())
        self.assertEqual(by_hash_pkg.read_bytes(), pkg_amd64.read_bytes())

    def test_external_attended_signature_retention(self):
        store_root = self.root / "signed_store"
        store = SignedStore(store_root, trust_config={"allowed_keys": {"synthetic-primary"}})

        repo_root = self.root / "repo"
        repo = build_apt_repository(repo_root, packages_bytes=[self.deb_amd64])

        sig_bytes = b"ATTENDED-PGP-DETACHED-SIGNATURE-BYTES"
        evidence = {"key_id": "0xABCDEF01", "operator": "ops-attended"}

        rec = repo.retain_external_signature(
            signed_store=store,
            signature_bytes=sig_bytes,
            inline=False,
            issuer="attended-signer-1",
            evidence=evidence,
            validator=lambda u, s, e: {"verified_issuer":"attended-signer-1","primary_key_id":"synthetic-primary"},
        )

        self.assertEqual(rec["rel_path"], "dists/resolute/Release.gpg")
        self.assertTrue((repo_root / "dists/resolute/Release.gpg").exists())
        self.assertEqual((repo_root / "dists/resolute/Release.gpg").read_bytes(), sig_bytes)

        status = repo.status()
        self.assertEqual(status["status"], "candidate")
        self.assertEqual(status["qualification"], "pending")
        self.assertFalse(status["is_live"])
        self.assertTrue(status["signed"])
        self.assertEqual(status["platform_scope"], "Ubuntu 26.04")
        self.assertFalse(status["debian_supported"])

        rec2 = repo.retain_external_signature(
            signed_store=store,
            signature_bytes=sig_bytes,
            inline=False,
            issuer="attended-signer-1",
            evidence=evidence,
            validator=lambda u, s, e: {"verified_issuer":"attended-signer-1","primary_key_id":"synthetic-primary"},
        )
        self.assertEqual(rec, rec2)

    def test_never_claims_live(self):
        repo_root = self.root / "repo"
        repo = build_apt_repository(repo_root, packages_bytes=[self.deb_amd64])
        with self.assertRaises(ContractError) as ctx:
            repo.claim_live()
        self.assertEqual(ctx.exception.code, "QUALIFICATION_PENDING")

    def test_tamper_detected_fail_closed(self):
        repo_root = self.root / "repo"
        build_apt_repository(repo_root, packages_bytes=[self.deb_amd64])

        pkg_file = repo_root / "dists/resolute/main/binary-amd64/Packages"
        pkg_file.write_bytes(pkg_file.read_bytes() + b"\n# Tamper")

        with self.assertRaises(ContractError) as ctx:
            validate_apt_repository(repo_root)
        self.assertEqual(ctx.exception.code, "TAMPER_DETECTED")

    def test_by_hash_tamper_detected(self):
        repo_root = self.root / "repo"
        build_apt_repository(repo_root, packages_bytes=[self.deb_amd64])

        dist_dir = repo_root / "dists/resolute"
        release_bytes = (dist_dir / "Release").read_bytes()
        import hashlib

        rel_sha = hashlib.sha256(release_bytes).hexdigest()
        by_hash_rel = dist_dir / f"by-hash/SHA256/{rel_sha}"
        by_hash_rel.write_bytes(b"CORRUPTED-BY-HASH-BYTES")

        with self.assertRaises(ContractError) as ctx:
            validate_apt_repository(repo_root)
        self.assertEqual(ctx.exception.code, "TAMPER_DETECTED")

    def test_packages_pool_tamper_detected(self):
        repo_root = self.root / "repo"
        build_apt_repository(repo_root, packages_bytes=[self.deb_amd64])

        # Find the deb in pool and tamper its bytes
        pool_deb = repo_root / "pool/main/h/hello-world/hello-world_1.0.0_amd64.deb"
        self.assertTrue(pool_deb.exists())
        pool_deb.write_bytes(pool_deb.read_bytes() + b"TAMPER")

        with self.assertRaises(ContractError) as ctx:
            validate_apt_repository(repo_root)
        self.assertIn(ctx.exception.code, ("TAMPER_DETECTED", "SIZE_MISMATCH"))

        # Test unindexed deb in pool
        repo_root2 = self.root / "repo2"
        build_apt_repository(repo_root2, packages_bytes=[self.deb_amd64])
        stray = repo_root2 / "pool/main/h/hello-world/stray_1.0.0_amd64.deb"
        stray.write_bytes(self.deb_arm64)

        with self.assertRaises(ContractError) as ctx:
            validate_apt_repository(repo_root2)
        self.assertEqual(ctx.exception.code, "UNINDEXED_PACKAGE")

    def test_malformed_deb_and_control(self):
        # Non-ar file
        with self.assertRaises(ContractError) as ctx:
            parse_deb_control(b"NOT_AN_AR_ARCHIVE")
        self.assertEqual(ctx.exception.code, "INVALID_DEB")

        # Symlink in control tar
        deb_sym = build_minimal_deb("pkg", "1.0", "amd64", symlink_in_control=True)
        with self.assertRaises(ContractError) as ctx:
            parse_deb_control(deb_sym)
        self.assertEqual(ctx.exception.code, "INVALID_DEB")

        # Duplicate control file in tar
        deb_dup = build_minimal_deb("pkg", "1.0", "amd64", duplicate_control=True)
        with self.assertRaises(ContractError) as ctx:
            parse_deb_control(deb_dup)
        self.assertEqual(ctx.exception.code, "INVALID_DEB")

        # CR in control file
        deb_cr = build_minimal_deb("pkg", "1.0", "amd64", custom_control=b"Package: pkg\r\nVersion: 1.0\r\nArchitecture: amd64\r\n")
        with self.assertRaises(ContractError) as ctx:
            parse_deb_control(deb_cr)
        self.assertEqual(ctx.exception.code, "INVALID_METADATA")

    def test_architecture_restrictions_ubuntu_2604(self):
        # amd64 and arm64 clients support architecture-independent packages.
        valid_amd64 = DebPackage("test-pkg", "1.0", "amd64", "pool/main/t/test/test_1.0_amd64.deb", 100, "0" * 64, "desc")
        self.assertEqual(valid_amd64.architecture, "amd64")

        valid_arm64 = DebPackage("test-pkg", "1.0", "arm64", "pool/main/t/test/test_1.0_arm64.deb", 100, "0" * 64, "desc")
        self.assertEqual(valid_arm64.architecture, "arm64")

        # Architecture-independent packages are supported on both target clients.
        valid_all = DebPackage("test-pkg", "1.0", "all", "pool/main/t/test/test_1.0_all.deb", 100, "0" * 64, "desc")
        self.assertEqual(valid_all.architecture, "all")
        for bad_arch in ("i386", "riscv64", "armhf", "ppc64le"):
            with self.subTest(arch=bad_arch):
                with self.assertRaises(ContractError) as ctx:
                    DebPackage("test-pkg", "1.0", bad_arch, f"pool/main/t/test/test_1.0_{bad_arch}.deb", 100, "0" * 64, "desc")
                self.assertEqual(ctx.exception.code, "INVALID_ARCHITECTURE")

    def test_cr_newline_injection_rejected(self):
        bad_values = ["hello\nworld", "hello\rworld", "hello\r\nworld"]
        for bad in bad_values:
            with self.subTest(val=bad):
                with self.assertRaises(ContractError) as ctx:
                    DebPackage(bad, "1.0", "amd64", "pool/main/p/p/p_1.0_amd64.deb", 100, "0" * 64, "desc")
                self.assertEqual(ctx.exception.code, "INVALID_METADATA")

                with self.assertRaises(ContractError) as ctx:
                    DebPackage("pkg", bad, "amd64", "pool/main/p/p/p_1.0_amd64.deb", 100, "0" * 64, "desc")
                self.assertEqual(ctx.exception.code, "INVALID_METADATA")

                with self.assertRaises(ContractError) as ctx:
                    DebPackage("pkg", "1.0", "amd64", "pool/main/p/p/p_1.0_amd64.deb", 100, "0" * 64, bad)
                self.assertEqual(ctx.exception.code, "INVALID_METADATA")

    def test_pages_scanner_integration(self):
        store_root = self.root / "signed_store"
        store = SignedStore(store_root, trust_config={"allowed_keys": {"synthetic-primary"}})

        pages_root = self.root / "pages_repo"
        repo_root = pages_root / "apt"
        repo = build_apt_repository(
            repo_root,
            packages_bytes=[self.deb_amd64, self.deb_arm64],
        )

        sig_bytes = b"PGP-SIGNATURE-BYTES"
        repo.retain_external_signature(
            signed_store=store,
            signature_bytes=sig_bytes,
            inline=False,
            issuer="attended-signer-1",
            evidence={"key": "k1"},
            validator=lambda u, s, e: {"verified_issuer":"attended-signer-1","primary_key_id":"synthetic-primary"},
        )

        (pages_root / "CNAME").write_text("rs9.knowledge-forge.ai\n")
        pubkey = (
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
        (pages_root / "keys").mkdir()
        (pages_root / "keys/rs9.asc").write_text(pubkey)
        (pages_root / "index.html").write_text("<html><body>APT Repository</body></html>\n")

        manifest = scan_pages_tree(pages_root)
        self.assertEqual(manifest["schema"], "rs9.pages-manifest.v1alpha1")
        self.assertGreater(manifest["file_count"], 0)

        leak = repo_root / "dists/resolute/leak_id_rsa"
        leak.write_text("-----" + "BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----\n")
        with self.assertRaises(ContractError) as ctx:
            scan_pages_tree(pages_root)
        self.assertIn(ctx.exception.code, ("CREDENTIAL_DETECTED", "PRIVATE_PAYLOAD_DETECTED", "DISALLOWED_FILE"))

    def test_installed_size_uses_actual_control_field_not_compressed_size(self):
        deb_with_inst_sz = build_minimal_deb(
            package="hello-size",
            version="1.0.0",
            architecture="amd64",
            installed_size=4096,
        )
        repo_root = self.root / "repo_size"
        repo = build_apt_repository(repo_root, packages_bytes=[deb_with_inst_sz])
        pkg = repo.packages[0]
        self.assertEqual(pkg.installed_size, 4096)
        self.assertNotEqual(pkg.installed_size, len(deb_with_inst_sz) // 1024 + 1)
        self.assertIn("Installed-Size: 4096", pkg.to_stanza())

        val = validate_apt_repository(repo_root)
        self.assertEqual(val["verified_packages"], 1)

        pkg_file = repo_root / "dists/resolute/main/binary-amd64/Packages"
        modified_pkgs = pkg_file.read_text().replace("Installed-Size: 4096", "Installed-Size: 9999")
        pkg_file.write_text(modified_pkgs)
        with self.assertRaises(ContractError) as ctx:
            validate_apt_repository(repo_root)
        self.assertEqual(ctx.exception.code, "TAMPER_DETECTED")

    def test_explicit_ubuntu_2604_scope_and_debian_rejection(self):
        repo_u26 = build_apt_repository(self.root / "repo_u26", distribution="resolute")
        self.assertEqual(repo_u26.status()["platform_scope"], "Ubuntu 26.04")
        self.assertFalse(repo_u26.status()["debian_supported"])

        for debian_dist in ("debian", "debian-13", "debian13", "trixie", "bookworm"):
            with self.subTest(distro=debian_dist):
                with self.assertRaises(ContractError) as ctx:
                    AptRepositoryCandidate(self.root / "bad_deb", distribution=debian_dist)
                self.assertEqual(ctx.exception.code, "UNSUPPORTED_PLATFORM")
                with self.assertRaises(ContractError) as ctx2:
                    validate_apt_repository(self.root / "repo_u26", distribution=debian_dist)
                self.assertEqual(ctx2.exception.code, "UNSUPPORTED_PLATFORM")


if __name__ == "__main__":
    unittest.main()
