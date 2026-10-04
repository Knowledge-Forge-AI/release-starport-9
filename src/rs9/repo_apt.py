"""Deterministic APT repository index and candidate generator.

Pool and dists hierarchy for Ubuntu 26.04 amd64 and arm64.
Deterministic Packages, Packages.gz, Packages.xz with SHA256 and Acquire-By-Hash.
Attended signing integration with SignedStore. Native qualification remains pending.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import lzma
import os
from pathlib import Path
import re
import stat
import tarfile
from typing import Any, Callable
import zlib

from rs9.errors import ContractError
from rs9.records import Record, snapshot, validate_bounded_int, validate_sanitized_string, validate_sha256
from rs9.scratch import canonical, physical_directory
from rs9.security import (
    validate_ecosystem_name,
    validate_nonproduction_key_path,
    validate_safe_relative_posix_path,
    validate_version_string,
)
from rs9.signed_store import SignedStore, _check_no_symlinks, _safe_read_file, _safe_write_file

ARCHITECTURES = ("amd64", "arm64")
PACKAGE_ARCHITECTURES = (*ARCHITECTURES, "all")
COMPONENTS = ("main",)
DEFAULT_DISTRIBUTION = "resolute"
SUPPORTED_DISTRIBUTIONS = ("resolute",)
DEFAULT_DATE = "Thu, 01 Jan 2026 00:00:00 +0000"
MAX_DEB_SIZE = 2 * 1024 * 1024 * 1024
MAX_AR_MEMBERS, MAX_TAR_MEMBERS, MAX_CONTROL_UNCOMPRESSED = 10, 50, 10 * 1024 * 1024


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class DebPackage:
    """Debian package metadata representation for Ubuntu 26.04 amd64/arm64."""

    def __init__(
        self, package: str, version: str, architecture: str, filename: str, size: int,
        sha256: str, description: str, maintainer: str = "Release Starport 9 <maintainer@example.com>",
        section: str = "utils", priority: str = "optional", installed_size: int | None = None,
        depends: str | None = None,
    ) -> None:
        for v in (package, version, architecture, maintainer, section, priority, filename, depends or ""):
            if "\r" in v or "\n" in v:
                raise ContractError("INVALID_METADATA", "CR or newline injection rejected")
        if "\r" in description or any(l and not l.startswith((" ", "\t")) for l in description.split("\n")[1:]):
            raise ContractError("INVALID_METADATA", "Description injection rejected")
        validate_ecosystem_name("apt", package)
        validate_version_string(version)
        if architecture not in PACKAGE_ARCHITECTURES:
            raise ContractError("INVALID_ARCHITECTURE", "Package architecture must be amd64, arm64 or all for Ubuntu 26.04")
        validate_safe_relative_posix_path(filename)
        validate_bounded_int(size, min_val=1, max_val=MAX_DEB_SIZE)
        validate_sha256(sha256)
        for s in (description, maintainer, section, priority):
            validate_sanitized_string(s, max_length=4096)

        self.package, self.version, self.architecture, self.filename = package, version, architecture, filename
        self.size, self.sha256, self.description, self.maintainer = size, sha256, description, maintainer
        self.section, self.priority, self.depends = section, priority, depends
        self.installed_size = installed_size
        if self.installed_size is not None:
            validate_bounded_int(self.installed_size, min_val=0, max_val=MAX_DEB_SIZE)

    def to_stanza(self) -> str:
        lines = [
            f"Package: {self.package}", f"Version: {self.version}", f"Architecture: {self.architecture}",
            f"Maintainer: {self.maintainer}",
        ]
        if self.installed_size is not None:
            lines.append(f"Installed-Size: {self.installed_size}")
        if self.depends:
            lines.append(f"Depends: {self.depends}")
        lines.extend([
            f"Section: {self.section}", f"Priority: {self.priority}", f"Filename: {self.filename}",
            f"Size: {self.size}", f"SHA256: {self.sha256}", f"Description: {self.description}",
        ])
        return "\n".join(lines)


def parse_deb_control(deb_bytes: bytes) -> dict[str, str]:
    """Parse Debian control fields with bounded ar/tar parsing and injection rejection."""
    if not isinstance(deb_bytes, bytes) or len(deb_bytes) > MAX_DEB_SIZE or not deb_bytes.startswith(b"!<arch>\n"):
        raise ContractError("INVALID_DEB", "Not a valid ar archive")

    offset, total_len, control_data, ar_count, ctrl_count = 8, len(deb_bytes), None, 0, 0
    names, control_name = set(), None
    while offset + 60 <= total_len:
        ar_count += 1
        if ar_count > MAX_AR_MEMBERS:
            raise ContractError("INVALID_DEB", "Too many ar archive members")
        name = deb_bytes[offset : offset + 16].decode("ascii", errors="replace").strip().rstrip("/")
        if deb_bytes[offset+58:offset+60] != b"`\n" or name in names:
            raise ContractError("INVALID_DEB", "Malformed or duplicate ar member")
        names.add(name)
        try:
            sz = int(deb_bytes[offset + 48 : offset + 58].decode("ascii", errors="replace").strip())
        except ValueError:
            raise ContractError("INVALID_DEB", "Malformed member size") from None
        offset += 60
        if sz < 0 or offset + sz > total_len:
            raise ContractError("INVALID_DEB", "Truncated member in deb")
        data = deb_bytes[offset : offset + sz]
        offset += sz + (sz % 2)
        if name in ("control.tar.gz", "control.tar.xz", "control.tar"):
            ctrl_count += 1
            if ctrl_count > 1:
                raise ContractError("INVALID_DEB", "Duplicate control archive member")
            control_data = data
            control_name = name
        elif name == "debian-binary" and data != b"2.0\n":
            raise ContractError("INVALID_DEB", "Unsupported Debian package format")

    if control_data is None or "debian-binary" not in names or offset != total_len:
        raise ContractError("INVALID_DEB", "Missing control archive")

    fields, ctrl_found, uncompressed = {}, 0, 0
    try:
        if control_name == "control.tar.gz":
            with gzip.GzipFile(fileobj=io.BytesIO(control_data)) as stream:
                control_data = stream.read(MAX_CONTROL_UNCOMPRESSED + 1)
        elif control_name == "control.tar.xz":
            with lzma.LZMAFile(io.BytesIO(control_data)) as stream:
                control_data = stream.read(MAX_CONTROL_UNCOMPRESSED + 1)
        if len(control_data) > MAX_CONTROL_UNCOMPRESSED:
            raise ContractError("INVALID_DEB", "Decompressed control archive exceeds bound")
        with tarfile.open(fileobj=io.BytesIO(control_data), mode="r:") as tar:
            for count, m in enumerate(tar, 1):
                if count > MAX_TAR_MEMBERS:
                    raise ContractError("INVALID_DEB", "Too many tar members")
                if m.issym() or m.islnk() or m.ischr() or m.isblk() or m.isfifo():
                    raise ContractError("INVALID_DEB", "Symlink or special file forbidden in control archive")
                if len(m.name) > 100:
                    raise ContractError("INVALID_DEB", "Tar member name exceeds limit")
                uncompressed += m.size
                if uncompressed > MAX_CONTROL_UNCOMPRESSED:
                    raise ContractError("INVALID_DEB", "Decompression size limit exceeded")
                if m.name in ("./control", "control"):
                    ctrl_found += 1
                    if ctrl_found > 1:
                        raise ContractError("INVALID_DEB", "Duplicate control file")
                    f = tar.extractfile(m)
                    if f is None:
                        raise ContractError("INVALID_DEB", "Failed extracting control file")
                    raw = f.read(MAX_CONTROL_UNCOMPRESSED + 1)
                    if len(raw) > MAX_CONTROL_UNCOMPRESSED or b"\r" in raw:
                        raise ContractError("INVALID_METADATA", "Control file invalid or CR detected")
                    cur_k = None
                    for line in raw.decode("utf-8").splitlines():
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith((" ", "\t")) and cur_k:
                            fields[cur_k] += "\n" + line
                        elif ":" in line:
                            cur_k, val = line.split(":", 1)
                            if cur_k.strip() in fields or not cur_k or cur_k != cur_k.strip() or not all(c.isascii() and (c.isalnum() or c == "-") for c in cur_k):
                                raise ContractError("INVALID_METADATA", "Duplicate or invalid control field")
                            cur_k, fields[cur_k.strip()] = cur_k.strip(), val.strip()
                        else:
                            raise ContractError("INVALID_METADATA", "Invalid control continuation")
    except ContractError:
        raise
    except Exception:
        raise ContractError("INVALID_DEB", "Failed parsing control archive") from None

    if ctrl_found != 1:
        raise ContractError("INVALID_DEB", "Single control file required")
    for req in ("Package", "Version", "Architecture"):
        if req not in fields:
            raise ContractError("INVALID_DEB", "Missing required control fields")
    if fields["Architecture"] not in PACKAGE_ARCHITECTURES:
        raise ContractError("INVALID_ARCHITECTURE", "Package architecture must be amd64, arm64 or all for Ubuntu 26.04")
    return fields


class AptRepositoryCandidate:
    """Deterministic candidate APT repository manager."""

    def __init__(
        self, root: str | Path, distribution: str = DEFAULT_DISTRIBUTION, origin: str = "RS9", label: str = "RS9"
    ) -> None:
        if distribution in ("debian", "debian-13", "debian13", "trixie", "bookworm"):
            raise ContractError("UNSUPPORTED_PLATFORM", "Debian is not supported; repository scope is explicitly Ubuntu 26.04")
        if distribution not in SUPPORTED_DISTRIBUTIONS:
            raise ContractError("INVALID_DISTRIBUTION", "LIVE1 APT requires Ubuntu 26.04 codename 'resolute'")
        for value in (origin, label):
            if "\n" in value or "\r" in value:
                raise ContractError("INVALID_METADATA", "Release field injection rejected")
            validate_sanitized_string(value)
        p = Path(root)
        p.mkdir(parents=True, exist_ok=True)
        self.root = physical_directory(p)
        _check_no_symlinks(self.root)
        self.distribution, self.origin, self.label, self.packages = distribution, origin, label, []
        self._is_signed, self._signed_objects = False, {}

    @property
    def is_signed(self) -> bool:
        return self._is_signed

    def add_package(
        self, deb_bytes: bytes | None = None, deb_file_path: Path | None = None, *, prefix: str | None = None
    ) -> DebPackage:
        if deb_bytes is None and deb_file_path is None:
            raise ContractError("INVALID_ARGUMENT", "deb_bytes or deb_file_path required")
        if deb_file_path is not None:
            _check_no_symlinks(deb_file_path)
            deb_bytes = _safe_read_file(deb_file_path)

        assert deb_bytes is not None
        control = parse_deb_control(deb_bytes)
        pkg_name, version, arch = control["Package"], control["Version"], control["Architecture"]
        desc, maintainer, depends = control.get("Description", "No description"), control.get("Maintainer", "RS9 <pkg@example.com>"), control.get("Depends")
        ctrl_installed_size = None
        if "Installed-Size" in control:
            try:
                ctrl_installed_size = int(control["Installed-Size"].strip())
            except ValueError:
                raise ContractError("INVALID_METADATA", "Installed-Size in control must be an integer")
            validate_bounded_int(ctrl_installed_size, min_val=0, max_val=MAX_DEB_SIZE)

        sha256, size = _digest(deb_bytes), len(deb_bytes)
        pkg_prefix = prefix or (pkg_name[:4] if pkg_name.startswith("lib") else pkg_name[0])
        filename = f"pool/main/{pkg_prefix}/{pkg_name}/{pkg_name}_{version}_{arch}.deb"
        validate_safe_relative_posix_path(filename)

        _safe_write_file(self.root / filename, deb_bytes)
        package_obj = DebPackage(
            package=pkg_name, version=version, architecture=arch, filename=filename,
            size=size, sha256=sha256, description=desc, maintainer=maintainer, depends=depends,
            installed_size=ctrl_installed_size,
        )
        self.packages.append(package_obj)
        return package_obj

    def build_indices(self, release_date: str = DEFAULT_DATE) -> dict[str, Any]:
        if "\n" in release_date or "\r" in release_date:
            raise ContractError("INVALID_METADATA", "Release date injection rejected")
        _check_no_symlinks(self.root)
        dist_dir = self.root / f"dists/{self.distribution}"
        dist_dir.mkdir(parents=True, exist_ok=True)
        _check_no_symlinks(dist_dir)

        index_entries: dict[str, tuple[str, int, bytes]] = {}
        for arch in ARCHITECTURES:
            arch_packages = [p for p in self.packages if p.architecture in (arch, "all")]
            arch_packages.sort(key=lambda p: (p.package, p.version, p.filename))

            txt = ("\n\n".join(p.to_stanza() for p in arch_packages) + "\n") if arch_packages else ""
            b_txt = txt.encode("utf-8")
            gz_buf = io.BytesIO()
            with gzip.GzipFile(filename="", mode="wb", fileobj=gz_buf, mtime=0) as gz:
                gz.write(b_txt)
            b_gz, b_xz = gz_buf.getvalue(), lzma.compress(b_txt, preset=6, check=lzma.CHECK_CRC64)

            c_rel = f"main/binary-{arch}"
            c_dir = dist_dir / c_rel
            h_dir = c_dir / "by-hash/SHA256"
            h_dir.mkdir(parents=True, exist_ok=True)

            for fname, bdata in (("Packages", b_txt), ("Packages.gz", b_gz), ("Packages.xz", b_xz)):
                sha = _digest(bdata)
                _safe_write_file(c_dir / fname, bdata)
                _safe_write_file(h_dir / sha, bdata)
                index_entries[f"{c_rel}/{fname}"] = (sha, len(bdata), bdata)

        release_lines = [
            f"Origin: {self.origin}", f"Label: {self.label}", f"Suite: {self.distribution}",
            f"Codename: {self.distribution}", f"Date: {release_date}", f"Architectures: {' '.join(ARCHITECTURES)}",
            f"Components: {' '.join(COMPONENTS)}", "Acquire-By-Hash: yes", "SHA256:",
        ] + [f" {index_entries[p][0]} {index_entries[p][1]} {p}" for p in sorted(index_entries)]

        release_bytes = ("\n".join(release_lines) + "\n").encode("utf-8")
        release_sha = _digest(release_bytes)
        _safe_write_file(dist_dir / "Release", release_bytes)

        dist_by_hash = dist_dir / "by-hash/SHA256"
        dist_by_hash.mkdir(parents=True, exist_ok=True)
        _check_no_symlinks(dist_by_hash)
        _safe_write_file(dist_by_hash / release_sha, release_bytes)

        return {
            "distribution": self.distribution, "release_sha256": release_sha,
            "release_bytes": release_bytes, "indices": {k: v[0] for k, v in index_entries.items()},
        }

    def retain_external_signature(
        self, signed_store: SignedStore, signature_bytes: bytes, *, inline: bool = False,
        issuer: str, evidence: dict[str, Any], validator: Callable[[bytes, bytes, dict[str, Any]], bool | dict[str, Any]] | None = None,
    ) -> Record:
        dist_dir = self.root / f"dists/{self.distribution}"
        release_file = dist_dir / "Release"
        if not release_file.exists():
            raise ContractError("MISSING_RELEASE", "Release file missing")

        release_bytes = _safe_read_file(release_file)
        rel_path = f"dists/{self.distribution}/{'InRelease' if inline else 'Release.gpg'}"
        target_file = dist_dir / ("InRelease" if inline else "Release.gpg")

        record = signed_store.retain(
            rel_path=rel_path, signed_bytes=signature_bytes, unsigned_bytes=release_bytes,
            issuer=issuer, evidence=evidence, validator=validator,
        )

        _safe_write_file(target_file, signature_bytes)
        dist_by_hash = dist_dir / "by-hash/SHA256"
        dist_by_hash.mkdir(parents=True, exist_ok=True)
        _safe_write_file(dist_by_hash / record["signed_sha256"], signature_bytes)

        self._is_signed, self._signed_objects[rel_path] = True, record["signed_sha256"]
        return record

    def sign_with_fixture(self, signer: Any) -> dict[str, Any]:
        """Write InRelease (clearsigned) and Release.gpg (detached, armored) from a fixture signer.

        The signer must be a NONPRODUCTION fixture authority exposing clearsign, detach_sign
        and verify; both signatures are verified against the exact Release bytes before the
        repository is marked signed. Signature objects also receive by-hash copies.
        """
        dist_dir = self.root / f"dists/{self.distribution}"
        release_file = dist_dir / "Release"
        if not release_file.exists():
            raise ContractError("MISSING_RELEASE", "Release file missing")
        release_bytes = _safe_read_file(release_file)
        inrelease = signer.clearsign(release_bytes)
        release_gpg = signer.detach_sign(release_bytes, armor=True)
        if clearsigned_body(inrelease).rstrip(b"\n") != release_bytes.rstrip(b"\n"):
            raise ContractError("SIGNATURE_BODY_MISMATCH", "InRelease body differs from Release")
        verified = signer.verify(inrelease)
        signer.verify(release_bytes, release_gpg)
        by_hash = dist_dir / "by-hash/SHA256"
        by_hash.mkdir(parents=True, exist_ok=True)
        for name, blob in (("InRelease", inrelease), ("Release.gpg", release_gpg)):
            _safe_write_file(dist_dir / name, blob)
            _safe_write_file(by_hash / _digest(blob), blob)
            self._signed_objects[f"dists/{self.distribution}/{name}"] = _digest(blob)
        self._is_signed = True
        return {
            "verified_issuer": verified.get("verified_issuer"),
            "inrelease_sha256": _digest(inrelease),
            "release_gpg_sha256": _digest(release_gpg),
            "release_sha256": _digest(release_bytes),
        }

    def status(self) -> dict[str, Any]:
        return {
            "status": "candidate", "qualification": "pending", "is_live": False,
            "platform_scope": "Ubuntu 26.04", "debian_supported": False,
            "distribution": self.distribution, "architectures": list(ARCHITECTURES),
            "components": list(COMPONENTS), "acquire_by_hash": True, "signed": self._is_signed,
            "packages_count": len(self.packages),
        }

    def claim_live(self) -> None:
        raise ContractError("QUALIFICATION_PENDING", "Native client qualification remains pending; no production platform qualification claims permitted")


def build_apt_repository(
    root: str | Path, packages_bytes: list[bytes] | None = None, *, distribution: str = DEFAULT_DISTRIBUTION,
    origin: str = "RS9", label: str = "RS9", release_date: str = DEFAULT_DATE,
) -> AptRepositoryCandidate:
    repo = AptRepositoryCandidate(root, distribution=distribution, origin=origin, label=label)
    for pdata in (packages_bytes or []):
        repo.add_package(deb_bytes=pdata)
    repo.build_indices(release_date=release_date)
    return repo


def validate_apt_repository(root: str | Path, distribution: str = DEFAULT_DISTRIBUTION) -> dict[str, Any]:
    """Validate candidate APT repository structure, hashes, and by-hash integrity.

    This structural validator checks file layout, checksum agreement, and pool package consistency;
    it explicitly does NOT verify cryptographic signatures or confer signature authentication.
    """
    if distribution in ("debian", "debian-13", "debian13", "trixie", "bookworm"):
        raise ContractError("UNSUPPORTED_PLATFORM", "Debian is not supported; repository scope is explicitly Ubuntu 26.04")
    if distribution not in SUPPORTED_DISTRIBUTIONS:
        raise ContractError("INVALID_DISTRIBUTION", "Unsupported distribution for Ubuntu 26.04 scope")
    root_path = physical_directory(root)
    _check_no_symlinks(root_path)

    dist_dir = root_path / f"dists/{distribution}"
    if not dist_dir.exists():
        raise ContractError("INVALID_REPO", "Distribution directory missing")
    release_file = dist_dir / "Release"
    if not release_file.exists():
        raise ContractError("INVALID_REPO", "Release file missing")

    release_bytes = _safe_read_file(release_file)
    release_sha = _digest(release_bytes)
    release_by_hash = dist_dir / f"by-hash/SHA256/{release_sha}"
    if not release_by_hash.exists() or _digest(_safe_read_file(release_by_hash)) != release_sha:
        raise ContractError("TAMPER_DETECTED", "Release by-hash file corrupted")

    lines = release_bytes.decode("utf-8").splitlines()
    in_sha256, index_manifest = False, {}
    for line in lines:
        if line == "SHA256:":
            in_sha256 = True
            continue
        if in_sha256:
            if not line.startswith(" "):
                break
            parts = line.strip().split()
            if len(parts) == 3:
                index_manifest[parts[2]] = (parts[0], int(parts[1]))

    for arch in ARCHITECTURES:
        for iname in ("Packages", "Packages.gz", "Packages.xz"):
            if f"main/binary-{arch}/{iname}" not in index_manifest:
                raise ContractError("INVALID_REPO", "Missing required index in Release")

    pool_packages_seen: set[str] = set()
    stanzas_by_arch: dict[str, list[dict[str, str]]] = {arch: [] for arch in ARCHITECTURES}
    for rel_path, (expected_sha, expected_size) in index_manifest.items():
        validate_safe_relative_posix_path(rel_path)
        tf = dist_dir / rel_path
        if not tf.exists():
            raise ContractError("MISSING_INDEX", "Index file missing")
        actual_bytes = _safe_read_file(tf)
        if len(actual_bytes) != expected_size or _digest(actual_bytes) != expected_sha:
            raise ContractError("TAMPER_DETECTED", "Hash or size mismatch for index file")
        if tf.name in ("Packages.gz", "Packages.xz"):
            try:
                decoded = gzip.decompress(actual_bytes) if tf.name.endswith(".gz") else lzma.decompress(actual_bytes)
            except (OSError, EOFError, lzma.LZMAError, zlib.error):
                raise ContractError("TAMPER_DETECTED", "Compressed index is not decodable") from None
            if decoded != _safe_read_file(tf.parent / "Packages"):
                raise ContractError("TAMPER_DETECTED", "Compressed index differs from Packages")

        bh_file = tf.parent / f"by-hash/SHA256/{expected_sha}"
        if not bh_file.exists():
            raise ContractError("MISSING_BY_HASH", "By-hash file missing")
        bh_bytes = _safe_read_file(bh_file)
        if len(bh_bytes) != expected_size or _digest(bh_bytes) != expected_sha:
            raise ContractError("TAMPER_DETECTED", "By-hash content corrupted")

        if tf.name == "Packages":
            pkg_text = actual_bytes.decode("utf-8")
            for stanza in [s.strip() for s in pkg_text.split("\n\n") if s.strip()]:
                fields: dict[str, str] = {}
                for sline in stanza.splitlines():
                    if ":" in sline:
                        k, v = sline.split(":", 1)
                        fields[k.strip()] = v.strip()
                deb_rel, sha, sz_s = fields.get("Filename"), fields.get("SHA256"), fields.get("Size")
                if not deb_rel or not sha or not sz_s:
                    raise ContractError("INVALID_METADATA", "Corrupted package stanza")
                index_arch = tf.parent.name.removeprefix("binary-")
                if index_arch not in stanzas_by_arch or fields.get("Architecture") not in (index_arch, "all"):
                    raise ContractError("INVALID_ARCHITECTURE", "Package listed in an index for a different architecture")
                stanzas_by_arch[index_arch].append(fields)

                validate_safe_relative_posix_path(deb_rel)
                pool_packages_seen.add(deb_rel)
                deb_path = root_path / deb_rel
                if not deb_path.exists():
                    raise ContractError("MISSING_PACKAGE", "Package file missing in pool")
                deb_content = _safe_read_file(deb_path)
                if len(deb_content) != int(sz_s) or _digest(deb_content) != sha:
                    raise ContractError("TAMPER_DETECTED", "Pool package content tampered")

                control = parse_deb_control(deb_content)
                if any(control.get(k) != fields.get(k) for k in ("Package", "Version", "Architecture")):
                    raise ContractError("TAMPER_DETECTED", "Package control metadata mismatch")
                if "Installed-Size" in control and fields.get("Installed-Size") != str(control["Installed-Size"]):
                    raise ContractError("TAMPER_DETECTED", "Package control Installed-Size mismatch")

    # Architecture-all packages must be advertised identically in every client architecture index.
    all_rows = [
        {(f.get("Package"), f.get("Version"), f.get("Filename"), f.get("SHA256"))
         for f in stanzas_by_arch[arch] if f.get("Architecture") == "all"}
        for arch in ARCHITECTURES
    ]
    if any(rows != all_rows[0] for rows in all_rows[1:]):
        raise ContractError("INVALID_REPO", "Architecture all packages must appear in every binary index")

    pool_root = root_path / "pool"
    if pool_root.exists():
        for cur, _, files in os.walk(str(pool_root)):
            for f in files:
                if f.endswith(".deb") and (Path(cur) / f).relative_to(root_path).as_posix() not in pool_packages_seen:
                    raise ContractError("UNINDEXED_PACKAGE", "Unindexed package file found in pool")

    return {
        "distribution": distribution,
        "release_sha256": release_sha,
        "verified_indices": len(index_manifest),
        "verified_packages": len(pool_packages_seen),
        "signature_authenticated": False,
        "confers_signature_authentication": False,
    }


def clearsigned_body(data: bytes) -> bytes:
    """Cleartext of a clearsigned document with dash-escaping removed (final newline excluded)."""
    marker = b"-----BEGIN PGP SIGNED MESSAGE-----\n"
    if not isinstance(data, bytes) or not data.startswith(marker):
        raise ContractError("INVALID_SIGNATURE_FORMAT", "Clearsigned document required")
    _, separator, rest = data[len(marker):].partition(b"\n\n")
    if not separator:
        raise ContractError("INVALID_SIGNATURE_FORMAT", "Clearsigned header terminator missing")
    body, separator, _ = rest.partition(b"\n-----BEGIN PGP SIGNATURE-----")
    if not separator:
        raise ContractError("INVALID_SIGNATURE_FORMAT", "Clearsigned signature block missing")
    return b"\n".join(line[2:] if line.startswith(b"- ") else line for line in body.split(b"\n"))


def verify_apt_signatures(
    root: str | Path, signer: Any, distribution: str = DEFAULT_DISTRIBUTION
) -> dict[str, Any]:
    """Structural validation plus cryptographic verification of InRelease and Release.gpg.

    ``signer.verify`` must perform real signature verification pinned to the fixture key;
    any failure, a missing signature object or a body that differs from Release is fatal.
    """
    structural = validate_apt_repository(root, distribution)
    dist_dir = physical_directory(root) / f"dists/{distribution}"
    release = _safe_read_file(dist_dir / "Release")
    blobs = {}
    for name in ("InRelease", "Release.gpg"):
        path = dist_dir / name
        if not path.exists():
            raise ContractError("MISSING_SIGNATURE", "Signed release object missing")
        blobs[name] = _safe_read_file(path)
        by_hash = dist_dir / f"by-hash/SHA256/{_digest(blobs[name])}"
        if not by_hash.exists() or _safe_read_file(by_hash) != blobs[name]:
            raise ContractError("MISSING_BY_HASH", "Signed release by-hash object missing or corrupted")
    if clearsigned_body(blobs["InRelease"]).rstrip(b"\n") != release.rstrip(b"\n"):
        raise ContractError("TAMPER_DETECTED", "InRelease body differs from Release")
    inline = signer.verify(blobs["InRelease"])
    signer.verify(release, blobs["Release.gpg"])
    return {
        **structural,
        "signature_authenticated": True,
        "confers_signature_authentication": False,
        "verified_issuer": inline.get("verified_issuer"),
        "inrelease_sha256": _digest(blobs["InRelease"]),
        "release_gpg_sha256": _digest(blobs["Release.gpg"]),
    }


_SOURCE_VALUE_RE = re.compile(r"^[A-Za-z0-9:/._@%+-]+$")


def apt_source_line(
    url: str, keyring_path: str, *, distribution: str = DEFAULT_DISTRIBUTION, arch: str | None = None
) -> str:
    """One-line APT source pinned to an explicit NONPRODUCTION keyring via signed-by."""
    validate_nonproduction_key_path(keyring_path)
    if distribution not in SUPPORTED_DISTRIBUTIONS:
        raise ContractError("INVALID_DISTRIBUTION", "LIVE1 APT requires Ubuntu 26.04 codename 'resolute'")
    if arch is not None and arch not in ARCHITECTURES:
        raise ContractError("INVALID_ARCHITECTURE", "APT client architecture must be amd64 or arm64")
    for value in (url, keyring_path):
        if not _SOURCE_VALUE_RE.fullmatch(value):
            raise ContractError("INVALID_METADATA", "APT source value contains unsafe characters")
    options = f"signed-by={keyring_path}" + (f" arch={arch}" if arch else "")
    return f"deb [{options}] {url} {distribution} main\n"


TAMPER_KINDS = ("package", "index", "signature", "wrongkey")


def tamper_apt_repository(
    root: str | Path, kind: str, *, distribution: str = DEFAULT_DISTRIBUTION, wrong_signer: Any = None,
    arch: str = "amd64", package: str | None = None,
) -> list[str]:
    """Corrupt a COPY of an assembled repository for fail-closed client tests.

    package: flip one byte of the first pool package (of ``package`` when named, so the
    client installs the tampered object); index: alter every Packages variant
    (and its by-hash object) of binary-<arch>, the client's own index; signature: corrupt
    InRelease and Release.gpg; wrongkey: replace both signatures with ones from ``wrong_signer``.
    Returns the changed repository-relative paths.
    """
    if kind not in TAMPER_KINDS:
        raise ContractError("INVALID_ARGUMENT", "Unsupported tamper kind")
    if arch not in ARCHITECTURES:
        raise ContractError("INVALID_ARCHITECTURE", "APT client architecture must be amd64 or arm64")
    if package is not None:
        validate_ecosystem_name("apt", package)
    base = physical_directory(root)
    dist_dir = base / f"dists/{distribution}"
    changed: list[str] = []

    def rewrite(path: Path, data: bytes) -> None:
        _safe_write_file(path, data)
        changed.append(path.relative_to(base).as_posix())

    if kind == "package":
        debs = sorted((base / "pool").rglob(f"{package}_*.deb" if package else "*.deb"))
        if not debs:
            raise ContractError("MISSING_PACKAGE", "No pool package to tamper")
        original = _safe_read_file(debs[0])
        rewrite(debs[0], original[:-1] + bytes([original[-1] ^ 0x01]))
    elif kind == "index":
        index_dir = dist_dir / f"main/binary-{arch}"
        for name in ("Packages", "Packages.gz", "Packages.xz"):
            original = _safe_read_file(index_dir / name)
            tampered = original + b"\n# tampered\n"
            rewrite(index_dir / name, tampered)
            rewrite(index_dir / f"by-hash/SHA256/{_digest(original)}", tampered)
    elif kind == "signature":
        for name in ("InRelease", "Release.gpg"):
            original = _safe_read_file(dist_dir / name)
            lines = original.split(b"\n")
            end = max(i for i, line in enumerate(lines) if line.startswith(b"-----END PGP SIGNATURE-----"))
            target = next(
                (i for i in range(end - 1, -1, -1)
                 if lines[i] and not lines[i].startswith((b"=", b"-")) and (len(lines[i]) > 6)),
                None,
            )
            if target is None:
                raise ContractError("INVALID_SIGNATURE_FORMAT", "No signature body line to tamper")
            line = bytearray(lines[target])
            line[5] = ord("A") if line[5] != ord("A") else ord("B")
            lines[target] = bytes(line)
            rewrite(dist_dir / name, b"\n".join(lines))
    else:
        if wrong_signer is None:
            raise ContractError("INVALID_ARGUMENT", "wrongkey tamper requires a different fixture signer")
        AptRepositoryCandidate(base, distribution=distribution).sign_with_fixture(wrong_signer)
        changed.extend(f"dists/{distribution}/{name}" for name in ("InRelease", "Release.gpg"))
    return changed
