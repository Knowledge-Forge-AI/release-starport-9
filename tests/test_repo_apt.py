"""Tests for deterministic APT repository index and candidate generator (rs9.repo_apt)."""

import gzip
import hashlib
import io
import lzma
import os
from pathlib import Path
import re
import shutil
import tarfile
import tempfile
import unittest

from rs9.errors import ContractError
from rs9.pages import scan_pages_tree
from rs9.repo_apt import (
    AptRepositoryCandidate,
    DebPackage,
    TAMPER_KINDS,
    apt_source_line,
    build_apt_repository,
    clearsigned_body,
    parse_deb_control,
    tamper_apt_repository,
    validate_apt_repository,
    verify_apt_signatures,
)
from rs9.signed_store import SignedStore
from rs9.signing_fixture import SigningFixture, find_gpg_binary


class FixtureSigner:
    """Key-bound signer double for SOURCE tests only; it is never a hosted-lane signing result.

    Signatures bind both the exact signed bytes and the key; verification is pinned to this
    key, mirroring how the real fixture's VALIDSIG pin behaves for the checks under test.
    """

    def __init__(self, fingerprint: str = "A" * 40) -> None:
        self.primary_fingerprint = fingerprint
        self.public_key_binary = bytes.fromhex(fingerprint[:8])
        self.public_key_armor = "fixture-public-key-" + fingerprint

    def _signature(self, data: bytes) -> str:
        return hashlib.sha256(self.primary_fingerprint.encode() + b"\0" + data).hexdigest()

    def detach_sign(self, data: bytes, *, armor: bool = True) -> bytes:
        return (f"-----BEGIN PGP SIGNATURE-----\n\nKEY:{self.primary_fingerprint}\n"
                f"SIG:{self._signature(data)}\n-----END PGP SIGNATURE-----\n").encode()

    def clearsign(self, data: bytes) -> bytes:
        body = data.rstrip(b"\n")
        return b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + body + b"\n" + self.detach_sign(body)

    def verify(self, signed: bytes, signature: bytes | None = None) -> dict:
        if signature is None:
            data = clearsigned_body(signed)
            signature = b"-----BEGIN PGP SIGNATURE-----" + signed.partition(b"\n-----BEGIN PGP SIGNATURE-----")[2]
        else:
            data = signed
        text = signature.decode("utf-8", errors="replace")
        key, sig = re.search(r"KEY:([0-9A-F]+)", text), re.search(r"SIG:([0-9a-f]+)", text)
        if key is None or key.group(1) != self.primary_fingerprint:
            raise ContractError("UNPINNED_TRUST", "Signature key is not the pinned fixture signer")
        if sig is None or sig.group(1) != self._signature(data):
            raise ContractError("VERIFICATION_FAILED", "Signature does not match the signed bytes")
        return {"verified_issuer": self.primary_fingerprint, "status": "valid"}


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
    compression: str = "xz",
    omit_control: bool = False,
    extra_members: list[tuple[str, bytes]] | None = None,
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

    def _populate_tar(tar: tarfile.TarFile) -> None:
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

    if compression == "xz":
        ctrl_buf = io.BytesIO()
        with tarfile.open(fileobj=ctrl_buf, mode="w:xz") as tar:
            _populate_tar(tar)
        control_bytes = ctrl_buf.getvalue()
        ctrl_name = "control.tar.xz"

        data_buf = io.BytesIO()
        with tarfile.open(fileobj=data_buf, mode="w:xz") as tar:
            ti = tarfile.TarInfo(name=f"./usr/bin/{package}")
            ti.size = len(payload_content)
            ti.mtime = 0
            ti.mode = 0o755
            tar.addfile(ti, io.BytesIO(payload_content))
        data_bytes = data_buf.getvalue()
        data_name = "data.tar.xz"
    elif compression == "plain":
        ctrl_buf = io.BytesIO()
        with tarfile.open(fileobj=ctrl_buf, mode="w:") as tar:
            _populate_tar(tar)
        control_bytes = ctrl_buf.getvalue()
        ctrl_name = "control.tar"

        data_buf = io.BytesIO()
        with tarfile.open(fileobj=data_buf, mode="w:") as tar:
            ti = tarfile.TarInfo(name=f"./usr/bin/{package}")
            ti.size = len(payload_content)
            ti.mtime = 0
            ti.mode = 0o755
            tar.addfile(ti, io.BytesIO(payload_content))
        data_bytes = data_buf.getvalue()
        data_name = "data.tar"
    elif compression in ("zst", "bz2", "lzma"):
        control_bytes = f"synthetic-{compression}-control-bytes".encode("ascii")
        ctrl_name = f"control.tar.{compression}"
        data_bytes = f"synthetic-{compression}-data-bytes".encode("ascii")
        data_name = f"data.tar.{compression}"
    else:
        # Default: gzip
        control_buf = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=control_buf, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tar:
                _populate_tar(tar)
        control_bytes = control_buf.getvalue()
        ctrl_name = "control.tar.gz"

        data_buf = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=data_buf, mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w") as tar:
                ti = tarfile.TarInfo(name=f"./usr/bin/{package}")
                ti.size = len(payload_content)
                ti.mtime = 0
                ti.mode = 0o755
                tar.addfile(ti, io.BytesIO(payload_content))
        data_bytes = data_buf.getvalue()
        data_name = "data.tar.gz"

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
    members: list[tuple[str, bytes]] = [("debian-binary", debian_binary)]
    if not omit_control:
        members.append((ctrl_name, control_bytes))
    members.append((data_name, data_bytes))
    if extra_members:
        members.extend(extra_members)

    for name, content in members:
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

    def test_parse_deb_control_xz_gzip_plain_supported(self):
        # xz compression
        deb_xz = build_minimal_deb("pkg-xz", "2.0.0", "amd64", description="XZ package", compression="xz")
        ctrl_xz = parse_deb_control(deb_xz)
        self.assertEqual(ctrl_xz["Package"], "pkg-xz")
        self.assertEqual(ctrl_xz["Version"], "2.0.0")
        self.assertEqual(ctrl_xz["Architecture"], "amd64")

        # gzip compression
        deb_gz = build_minimal_deb("pkg-gz", "2.0.0", "amd64", description="GZ package", compression="gz")
        ctrl_gz = parse_deb_control(deb_gz)
        self.assertEqual(ctrl_gz["Package"], "pkg-gz")
        self.assertEqual(ctrl_gz["Version"], "2.0.0")

        # plain uncompressed tar
        deb_plain = build_minimal_deb("pkg-plain", "2.0.0", "amd64", description="Plain tar package", compression="plain")
        ctrl_plain = parse_deb_control(deb_plain)
        self.assertEqual(ctrl_plain["Package"], "pkg-plain")
        self.assertEqual(ctrl_plain["Version"], "2.0.0")

    def test_parse_deb_control_zst_rejected_with_precise_diagnostic(self):
        deb_zst = build_minimal_deb("pkg-zst", "1.0.0", "amd64", compression="zst")
        with self.assertRaises(ContractError) as ctx:
            parse_deb_control(deb_zst)
        self.assertEqual(ctx.exception.code, "INVALID_DEB")
        self.assertEqual(ctx.exception.message, "Unsupported control compression")
        self.assertNotEqual(ctx.exception.message, "Missing control archive")
        self.assertEqual(ctx.exception.details.get("diagnostic_token"), "unsupported-control-compression")
        self.assertEqual(ctx.exception.details.get("reason_token"), "unsupported-control-compression")
        self.assertEqual(ctx.exception.details.get("reason"), "unsupported-control-compression")
        self.assertEqual(ctx.exception.details.get("archive_path"), "control.tar.zst")

    def test_parse_deb_control_other_recognizable_unsupported_compressions(self):
        for unsupported_fmt in ("bz2", "lzma"):
            with self.subTest(fmt=unsupported_fmt):
                deb_other = build_minimal_deb("pkg-other", "1.0.0", "amd64", compression=unsupported_fmt)
                with self.assertRaises(ContractError) as ctx:
                    parse_deb_control(deb_other)
                self.assertEqual(ctx.exception.code, "INVALID_DEB")
                self.assertEqual(ctx.exception.message, "Unsupported control compression")
                self.assertEqual(ctx.exception.details.get("diagnostic_token"), "unsupported-control-compression")
                self.assertEqual(ctx.exception.details.get("archive_path"), f"control.tar.{unsupported_fmt}")

    def test_parse_deb_control_missing_control_archive_distinction(self):
        deb_no_ctrl = build_minimal_deb("pkg-noctrl", "1.0.0", "amd64", omit_control=True)
        with self.assertRaises(ContractError) as ctx:
            parse_deb_control(deb_no_ctrl)
        self.assertEqual(ctx.exception.code, "INVALID_DEB")
        self.assertEqual(ctx.exception.message, "Missing control archive")
        self.assertNotIn("diagnostic_token", ctx.exception.details)

    def test_parse_deb_control_duplicate_control_with_unsupported_format(self):
        deb_dup = build_minimal_deb(
            "pkg-dup", "1.0.0", "amd64", compression="xz",
            extra_members=[("control.tar.zst", b"zstd-payload")]
        )
        with self.assertRaises(ContractError) as ctx:
            parse_deb_control(deb_dup)
        self.assertEqual(ctx.exception.code, "INVALID_DEB")
        self.assertEqual(ctx.exception.message, "Duplicate control archive member")

    def test_apt_repository_candidate_rejects_zst_package(self):
        repo_root = self.root / "zst_candidate_repo"
        repo = AptRepositoryCandidate(repo_root)
        deb_zst = build_minimal_deb("zst-pkg", "1.0.0", "amd64", compression="zst")
        with self.assertRaises(ContractError) as ctx:
            repo.add_package(deb_bytes=deb_zst)
        self.assertEqual(ctx.exception.code, "INVALID_DEB")
        self.assertEqual(ctx.exception.details.get("diagnostic_token"), "unsupported-control-compression")

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


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rewrite_index(root: Path, arch: str, *, plain: bytes | None = None, gz: bytes | None = None) -> None:
    """Replace an arch index consistently (Release hashes, by-hash objects) to test deeper invariants."""
    dist = root / "dists/resolute"
    directory = dist / f"main/binary-{arch}"
    names = ("Packages", "Packages.gz", "Packages.xz")
    current = {name: (directory / name).read_bytes() for name in names}
    plain_bytes = plain if plain is not None else current["Packages"]
    replacement = {
        "Packages": plain_bytes,
        "Packages.gz": gz if gz is not None else gzip.compress(plain_bytes, mtime=0),
        "Packages.xz": lzma.compress(plain_bytes, preset=6, check=lzma.CHECK_CRC64),
    }
    release = (dist / "Release").read_text("utf-8")
    for name, data in replacement.items():
        (directory / name).write_bytes(data)
        (directory / "by-hash/SHA256" / _sha(data)).write_bytes(data)
        release = release.replace(
            f" {_sha(current[name])} {len(current[name])} main/binary-{arch}/{name}",
            f" {_sha(data)} {len(data)} main/binary-{arch}/{name}",
        )
    release_bytes = release.encode("utf-8")
    (dist / "Release").write_bytes(release_bytes)
    (dist / "by-hash/SHA256" / _sha(release_bytes)).write_bytes(release_bytes)


class FixtureSigningAndClientTests(unittest.TestCase):
    """Signed-repository, tamper and architecture-all invariants (signer double; see FixtureSigner)."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        self.debs = [
            build_minimal_deb("hello-world", "1.0.0", "amd64", payload_content=b"amd64-bytes"),
            build_minimal_deb("hello-world", "1.0.0", "arm64", payload_content=b"arm64-bytes"),
            build_minimal_deb("tf-cli", "1.0.0", "all", depends="nodejs (>= 22)", payload_content=b"cli-bytes"),
        ]
        self.signer = FixtureSigner()

    def tearDown(self):
        self.temp_dir.cleanup()

    def signed_repo(self, name: str = "signed") -> Path:
        root = self.root / name
        repo = build_apt_repository(root, packages_bytes=self.debs)
        repo.sign_with_fixture(self.signer)
        return root

    def test_sign_with_fixture_writes_signed_objects_and_by_hash(self):
        root = self.root / "signed"
        repo = build_apt_repository(root, packages_bytes=self.debs)
        self.assertFalse(repo.is_signed)
        evidence = repo.sign_with_fixture(self.signer)
        self.assertTrue(repo.is_signed)
        dist = root / "dists/resolute"
        release = (dist / "Release").read_bytes()
        inrelease, release_gpg = (dist / "InRelease").read_bytes(), (dist / "Release.gpg").read_bytes()
        self.assertEqual(clearsigned_body(inrelease).rstrip(b"\n"), release.rstrip(b"\n"))
        self.assertEqual(evidence["inrelease_sha256"], _sha(inrelease))
        self.assertEqual(evidence["release_gpg_sha256"], _sha(release_gpg))
        for blob in (inrelease, release_gpg, release):
            self.assertEqual((dist / "by-hash/SHA256" / _sha(blob)).read_bytes(), blob)
        verified = verify_apt_signatures(root, self.signer)
        self.assertTrue(verified["signature_authenticated"])
        self.assertEqual(verified["verified_issuer"], self.signer.primary_fingerprint)
        self.assertEqual(verified["verified_packages"], 3)
        # Structural validation alone still never claims signature authentication.
        self.assertFalse(validate_apt_repository(root)["signature_authenticated"])

    def test_unsigned_repository_has_no_authenticated_signature(self):
        root = self.root / "unsigned"
        build_apt_repository(root, packages_bytes=self.debs)
        with self.assertRaises(ContractError) as caught:
            verify_apt_signatures(root, self.signer)
        self.assertEqual(caught.exception.code, "MISSING_SIGNATURE")

    def test_every_tamper_kind_is_rejected_fail_closed(self):
        expected = {"package": {"TAMPER_DETECTED"}, "index": {"TAMPER_DETECTED"},
                    "signature": {"MISSING_BY_HASH", "VERIFICATION_FAILED"}, "wrongkey": {"UNPINNED_TRUST"}}
        self.assertEqual(set(TAMPER_KINDS), set(expected))
        original = self.signed_repo()
        for arch in ("amd64", "arm64"):
            for kind, codes in expected.items():
                with self.subTest(kind=kind, arch=arch):
                    copy = self.root / f"tampered-{kind}-{arch}"
                    shutil.copytree(original, copy)
                    changed = tamper_apt_repository(copy, kind, arch=arch, wrong_signer=FixtureSigner("B" * 40),
                                                    package="hello-world")
                    self.assertTrue(changed)
                    with self.assertRaises(ContractError) as caught:
                        verify_apt_signatures(copy, self.signer)
                    self.assertIn(caught.exception.code, codes)
        verify_apt_signatures(original, self.signer)  # the untouched original still verifies

    def test_signature_corruption_is_caught_by_cryptographic_verification(self):
        copy = self.root / "corrupt-signature"
        shutil.copytree(self.signed_repo(), copy)
        tamper_apt_repository(copy, "signature")
        dist = copy / "dists/resolute"
        with self.assertRaises(ContractError) as inline:
            self.signer.verify((dist / "InRelease").read_bytes())
        with self.assertRaises(ContractError) as detached:
            self.signer.verify((dist / "Release").read_bytes(), (dist / "Release.gpg").read_bytes())
        self.assertEqual(inline.exception.code, "VERIFICATION_FAILED")
        self.assertEqual(detached.exception.code, "VERIFICATION_FAILED")

    def test_wrong_key_signature_is_valid_for_its_own_key_but_unpinned(self):
        copy = self.root / "wrong-key"
        shutil.copytree(self.signed_repo(), copy)
        other = FixtureSigner("C" * 40)
        tamper_apt_repository(copy, "wrongkey", wrong_signer=other)
        verify_apt_signatures(copy, other)
        with self.assertRaises(ContractError):
            verify_apt_signatures(copy, self.signer)
        with self.assertRaises(ContractError) as missing:
            tamper_apt_repository(copy, "wrongkey")
        self.assertEqual(missing.exception.code, "INVALID_ARGUMENT")

    def test_tamper_arguments_are_validated(self):
        root = self.signed_repo()
        for kwargs in ({"kind": "other"}, {"kind": "index", "arch": "armhf"}, {"kind": "package", "package": "../x"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ContractError):
                tamper_apt_repository(root, **kwargs)

    def test_architecture_all_is_indexed_identically_in_both_architectures(self):
        root = self.signed_repo()
        dist = root / "dists/resolute/main"
        amd64 = (dist / "binary-amd64/Packages").read_text("utf-8")
        arm64 = (dist / "binary-arm64/Packages").read_text("utf-8")
        self.assertIn("Package: tf-cli", amd64)
        self.assertIn("Package: tf-cli", arm64)
        self.assertEqual(amd64.count("Architecture: all"), 1)
        self.assertEqual(arm64.count("Architecture: all"), 1)
        self.assertIn("Architecture: amd64", amd64)
        self.assertNotIn("Architecture: arm64", amd64)
        self.assertNotIn("Architecture: amd64", arm64)
        self.assertEqual(validate_apt_repository(root)["verified_packages"], 3)

    def test_architecture_all_missing_from_one_index_is_rejected(self):
        root = self.root / "missing-all"
        build_apt_repository(root, packages_bytes=self.debs)
        arm64 = (root / "dists/resolute/main/binary-arm64/Packages").read_text("utf-8")
        stanzas = [s for s in arm64.strip().split("\n\n") if "Architecture: all" not in s]
        rewrite_index(root, "arm64", plain=("\n\n".join(stanzas) + "\n").encode("utf-8"))
        with self.assertRaises(ContractError) as caught:
            validate_apt_repository(root)
        self.assertEqual(caught.exception.code, "INVALID_REPO")

    def test_foreign_architecture_stanza_is_rejected(self):
        root = self.root / "foreign"
        build_apt_repository(root, packages_bytes=self.debs)
        amd64 = (root / "dists/resolute/main/binary-amd64/Packages").read_text("utf-8")
        stanzas = amd64.strip().split("\n\n")
        arm64_stanza = next(s for s in (root / "dists/resolute/main/binary-arm64/Packages").read_text("utf-8")
                            .strip().split("\n\n") if "Architecture: arm64" in s)
        rewrite_index(root, "amd64", plain=("\n\n".join([*stanzas, arm64_stanza]) + "\n").encode("utf-8"))
        with self.assertRaises(ContractError) as caught:
            validate_apt_repository(root)
        self.assertEqual(caught.exception.code, "INVALID_ARCHITECTURE")

    def test_compressed_index_must_decode_to_packages(self):
        root = self.root / "decoy-gz"
        build_apt_repository(root, packages_bytes=self.debs)
        rewrite_index(root, "amd64", gz=gzip.compress(b"Package: decoy\n", mtime=0))
        with self.assertRaises(ContractError) as caught:
            validate_apt_repository(root)
        self.assertEqual(caught.exception.code, "TAMPER_DETECTED")
        root2 = self.root / "bad-gz"
        build_apt_repository(root2, packages_bytes=self.debs)
        rewrite_index(root2, "amd64", gz=b"not gzip")
        with self.assertRaises(ContractError):
            validate_apt_repository(root2)

    def test_clearsigned_body_unescapes_dashes_and_rejects_non_clearsigned(self):
        document = (b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nline one\n- -dash line\nlast"
                    b"\n-----BEGIN PGP SIGNATURE-----\n\nSIG\n-----END PGP SIGNATURE-----\n")
        self.assertEqual(clearsigned_body(document), b"line one\n-dash line\nlast")
        for bad in (b"plain", b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\nno separator",
                    b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nbody without signature"):
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                clearsigned_body(bad)

    def test_apt_source_line_requires_nonproduction_keyring_and_safe_values(self):
        line = apt_source_line("file:/srv/rs9/apt", "/etc/apt/keyrings/rs9-nonproduction.gpg", arch="arm64")
        self.assertEqual(line, "deb [signed-by=/etc/apt/keyrings/rs9-nonproduction.gpg arch=arm64] "
                               "file:/srv/rs9/apt resolute main\n")
        for keyring in ("/etc/apt/keyrings/rs9.gpg", "/usr/share/keyrings/production/rs9-nonproduction.gpg"):
            with self.subTest(keyring=keyring), self.assertRaises(ContractError) as caught:
                apt_source_line("file:/srv/rs9/apt", keyring)
            self.assertEqual(caught.exception.code, "KEY_PATH_NOT_NONPRODUCTION")
        for kwargs in ({"url": "file:/x y"}, {"url": "file:/x\nbad"}, {"url": "http://h/;rm"},
                       {"distribution": "trixie"}, {"arch": "armhf"}):
            args = {"url": "file:/srv/rs9/apt", "keyring": "/etc/apt/keyrings/rs9-nonproduction.gpg", **kwargs}
            with self.subTest(kwargs=kwargs), self.assertRaises(ContractError):
                apt_source_line(args["url"], args["keyring"], **{k: v for k, v in kwargs.items() if k != "url"})

    def test_real_gnupg_fixture_signs_and_rejects_every_tamper(self):
        binary = find_gpg_binary()
        if not binary:
            self.skipTest("GnuPG binary not available")
        try:
            fixture = SigningFixture(gpg_binary=binary)
            wrong = SigningFixture(gpg_binary=binary, user_id="RS9 NON-PRODUCTION WRONG KEY <nonproduction@invalid>")
        except ContractError as error:
            if error.code == "GPG_AGENT_UNAVAILABLE":
                self.skipTest("GnuPG agent unavailable")
            raise
        with fixture, wrong:
            root = self.root / "real-gpg"
            repo = build_apt_repository(root, packages_bytes=self.debs)
            repo.sign_with_fixture(fixture)
            self.assertTrue(verify_apt_signatures(root, fixture)["signature_authenticated"])
            for kind in TAMPER_KINDS:
                with self.subTest(kind=kind):
                    copy = self.root / f"real-{kind}"
                    shutil.copytree(root, copy)
                    tamper_apt_repository(copy, kind, wrong_signer=wrong, package="hello-world")
                    with self.assertRaises(ContractError):
                        verify_apt_signatures(copy, fixture)


if __name__ == "__main__":
    unittest.main()
