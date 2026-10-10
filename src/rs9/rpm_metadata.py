"""Bounded verification of the candidate's gzip RPM metadata contract."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
import xml.etree.ElementTree as ET
import zlib

from rs9.errors import ContractError

REQUIRED_DATA_TYPES = {"primary", "filelists", "other"}
GZIP_MAGIC = b"\x1f\x8b"
SHA256_HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
REPO_NS = "http://linux.duke.edu/metadata/repo"
NAMESPACES = {"primary": "http://linux.duke.edu/metadata/common",
              "filelists": "http://linux.duke.edu/metadata/filelists",
              "other": "http://linux.duke.edu/metadata/other"}
MAX_PACKAGES = 4096
MAX_PACKAGE_BYTES = 2 * 1024**3


class _Verifier:
    def __init__(self, root, receipt, xml_limit, open_limit):
        self.root, self.receipt = Path(root), receipt
        self.xml_limit = min(xml_limit, 1024**2)
        self.open_limit = min(open_limit, 64 * 1024**2)
        if self.xml_limit <= 0 or self.open_limit <= 0:
            raise ValueError("metadata limits must be positive")

    def fail(self, stage, code, target="repodata"):
        # Never reflect arbitrary XML strings, OS exception text or private paths.
        safe = re.fullmatch(r"(?:repodata|Packages|x86_64|aarch64|noarch)(?:/[A-Za-z0-9._+-]{1,200})?", str(target))
        details = {"operation": "repodata-format-verify", "substage": stage,
                   "causal_code": code, "target": target if safe else "repodata"}
        if not safe:
            details["path_sha256"] = hashlib.sha256(str(target).encode("utf-8", "surrogatepass")).hexdigest()
        if self.receipt is not None:
            details.update(exit_code=self.receipt.exit_code,
                           stdout_sha256=self.receipt.stdout_sha256,
                           stderr_sha256=self.receipt.stderr_sha256, tool="createrepo_c")
        err = ContractError("RPM_REPOSITORY_OPERATION", "Candidate RPM metadata verification failed", details=details)
        if self.receipt is not None:
            err.receipt = self.receipt
        raise err

    def physical(self, rel, *, directory=False):
        path = self.root / rel
        try:
            # Include all parents to prevent a physical child under a symlink.
            for parent in (path.parent, *path.parent.parents):
                if not stat.S_ISDIR(parent.lstat().st_mode):
                    self.fail("repodata-inventory", "SYMLINK_REJECTED", rel)
            st = path.lstat()
            valid = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
            if not valid:
                self.fail("repodata-inventory", "SYMLINK_REJECTED", rel)
            return path, st
        except FileNotFoundError:
            self.fail("repodata-inventory", "MISSING_OBJECT", rel)
        except OSError:
            self.fail("repodata-inventory", "READ_FAILED", rel)

    def read(self, rel, limit):
        path, st = self.physical(rel)
        if st.st_size > limit:
            self.fail("xml-bounds", "SIZE_EXCEEDED", rel)
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                data = stream.read(limit + 1)
        except OSError:
            self.fail("repodata-inventory", "READ_FAILED", rel)
        if len(data) > limit or len(data) != st.st_size:
            self.fail("xml-bounds", "SIZE_EXCEEDED", rel)
        return data

    def xml(self, data, target):
        if b"<!DOCTYPE" in data.upper():
            self.fail("xml-dtd-forbidden", "DTD_FORBIDDEN", target)
        if b"<!ENTITY" in data.upper():
            self.fail("xml-entity-forbidden", "ENTITY_FORBIDDEN", target)
        try:
            text = data.decode("utf-8", "strict")
            if "\x00" in text:
                raise ValueError("unsupported encoding")
            return ET.fromstring(text)
        except (ET.ParseError, UnicodeError, ValueError):
            self.fail("xml-parse", "INVALID_XML", target)

    def child(self, node, ns, name, target):
        matches = node.findall(f"{{{ns}}}{name}")
        if len(matches) != 1:
            self.fail("xml-parse", "AMBIGUOUS_FIELD", target)
        return matches[0]

    def number(self, value, stage, target):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,20}", value):
            self.fail(stage, "INVALID_SIZE", target)
        return int(value)

    def checksum(self, node, ns, field, target):
        child = self.child(node, ns, field, target)
        if child.get("type") != "sha256" or not SHA256_HEX_RE.fullmatch(child.text or ""):
            self.fail("checksum-verify", "INVALID_CHECKSUM", target)
        return child.text

    def package_href(self, href):
        if not isinstance(href, str) or not re.fullmatch(r"(?:Packages|x86_64|aarch64|noarch)/[A-Za-z0-9._+-]{1,200}\.rpm", href):
            self.fail("package-inventory", "UNSAFE_HREF", href)
        return href

    def package_hash(self, href, size):
        path = self.root / href
        if not path.exists():
            self.fail("package-inventory", "MISSING_PACKAGE", href)
        path, st = self.physical(href)
        if size != st.st_size:
            self.fail("package-inventory", "PACKAGE_SIZE_MISMATCH", href)
        if size > MAX_PACKAGE_BYTES:
            self.fail("package-inventory", "SIZE_EXCEEDED", href)
        digest = hashlib.sha256()
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                remaining = size
                while remaining:
                    chunk = stream.read(min(1024**2, remaining))
                    if not chunk:
                        self.fail("package-inventory", "PACKAGE_SIZE_MISMATCH", href)
                    digest.update(chunk)
                    remaining -= len(chunk)
                if stream.read(1):
                    self.fail("package-inventory", "PACKAGE_SIZE_MISMATCH", href)
        except OSError:
            self.fail("package-inventory", "READ_FAILED", href)
        return digest.hexdigest()

    def physical_packages(self):
        found = set()
        for name in ("Packages", "x86_64", "aarch64", "noarch"):
            if not os.path.lexists(self.root / name):
                continue
            directory, _ = self.physical(name, directory=True)
            with os.scandir(directory) as entries:
                for i, entry in enumerate(entries):
                    if i >= MAX_PACKAGES:
                        self.fail("package-inventory", "SIZE_EXCEEDED", name)
                    if entry.name.endswith(".rpm"):
                        href = self.package_href(f"{name}/{entry.name}")
                        self.physical(href)
                        found.add(href)
        return found

    def verify(self, expected, signed):
        raw = self.read("repodata/repomd.xml", self.xml_limit)
        repomd = self.xml(raw, "repodata/repomd.xml")
        if repomd.tag != f"{{{REPO_NS}}}repomd":
            self.fail("repomd-parse", "INVALID_ROOT")
        objects = {}
        for node in repomd.findall(f"{{{REPO_NS}}}data"):
            kind = node.get("type")
            if kind not in REQUIRED_DATA_TYPES or kind in objects:
                self.fail("repomd-parse", "UNEXPECTED_DATA_TYPE")
            href = self.child(node, REPO_NS, "location", "repodata").get("href", "")
            if not re.fullmatch(r"repodata/[A-Za-z0-9._+-]{1,200}", href):
                self.fail("repomd-parse", "UNSAFE_HREF", href)
            if not href.endswith(".xml.gz"):
                self.fail("compression-verify", "BAD_COMPRESSION", href)
            if href in {o["href"] for o in objects.values()}:
                self.fail("repomd-parse", "UNEXPECTED_OBJECT", href)
            objects[kind] = {
                "href": href, "sha256": self.checksum(node, REPO_NS, "checksum", href),
                "open_sha256": self.checksum(node, REPO_NS, "open-checksum", href),
                "size": self.number(self.child(node, REPO_NS, "size", href).text, "checksum-verify", href),
                "open_size": self.number(self.child(node, REPO_NS, "open-size", href).text, "decompression-verify", href)}
        if set(objects) != REQUIRED_DATA_TYPES:
            self.fail("repomd-parse", "MISSING_DATA_TYPE")
        directory, _ = self.physical("repodata", directory=True)
        actual = set()
        with os.scandir(directory) as entries:
            for i, entry in enumerate(entries):
                if i >= 16:
                    self.fail("repodata-inventory", "UNEXPECTED_OBJECT")
                rel = f"repodata/{entry.name}"
                self.physical(rel)
                actual.add(rel)
        wanted = {"repodata/repomd.xml", *(o["href"] for o in objects.values())}
        if signed:
            wanted.add("repodata/repomd.xml.asc")
        elif "repodata/repomd.xml.asc" in actual:
            self.fail("repodata-inventory", "UNEXPECTED_SIGNATURE", "repodata/repomd.xml.asc")
        if actual - wanted:
            self.fail("repodata-inventory", "UNEXPECTED_OBJECT", sorted(actual - wanted)[0])
        if wanted - actual:
            self.fail("repodata-inventory", "MISSING_OBJECT", sorted(wanted - actual)[0])
        roots = {}
        for kind, obj in objects.items():
            href = obj["href"]
            data = self.read(href, 64 * 1024**2)
            if not data.startswith(GZIP_MAGIC):
                self.fail("compression-verify", "BAD_COMPRESSION", href)
            if len(data) != obj["size"]:
                self.fail("checksum-verify", "SIZE_MISMATCH", href)
            if hashlib.sha256(data).hexdigest() != obj["sha256"]:
                self.fail("checksum-verify", "CHECKSUM_MISMATCH", href)
            # Only the fixed producer bound controls allocation, never open-size.
            inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                opened = inflater.decompress(data, self.open_limit + 1)
            except zlib.error:
                self.fail("decompression-verify", "DECOMPRESSION_FAILED", href)
            if len(opened) > self.open_limit or inflater.unconsumed_tail:
                self.fail("decompression-verify", "SIZE_EXCEEDED", href)
            if not inflater.eof:
                self.fail("decompression-verify", "DECOMPRESSION_FAILED", href)
            if inflater.unused_data:
                self.fail("decompression-verify", "TRAILING_GARBAGE", href)
            if len(opened) != obj["open_size"]:
                self.fail("decompression-verify", "OPEN_SIZE_MISMATCH", href)
            if hashlib.sha256(opened).hexdigest() != obj["open_sha256"]:
                self.fail("decompression-verify", "OPEN_CHECKSUM_MISMATCH", href)
            roots[kind] = self.xml(opened, href)
            obj["compression"] = "gzip"
        primary, hrefs = {}, set()
        for kind in ("primary", "filelists", "other"):
            root = roots[kind]
            ns = NAMESPACES[kind]
            tag = {"primary": "metadata", "filelists": "filelists", "other": "otherdata"}[kind]
            if root.tag != f"{{{ns}}}{tag}":
                self.fail("metadata-linkage", "INVALID_ROOT")
            packages = root.findall(f"{{{ns}}}package")
            count = self.number(root.get("packages"), "metadata-linkage", "repodata")
            if count != len(packages) or count > MAX_PACKAGES:
                self.fail("metadata-linkage", "PACKAGE_COUNT_MISMATCH")
            linked = {}
            for pkg in packages:
                ver = self.child(pkg, ns, "version", "repodata")
                if kind == "primary":
                    checksum = self.child(pkg, ns, "checksum", "repodata")
                    pkgid = self.checksum(pkg, ns, "checksum", "repodata")
                    if checksum.get("pkgid") != "YES" or pkg.get("type") != "rpm":
                        self.fail("metadata-linkage", "INVALID_PACKAGE")
                    name = self.child(pkg, ns, "name", "repodata").text
                    arch = self.child(pkg, ns, "arch", "repodata").text
                    href = self.package_href(self.child(pkg, ns, "location", "repodata").get("href"))
                    if href in hrefs:
                        self.fail("metadata-linkage", "PACKAGE_INVENTORY_MISMATCH")
                    hrefs.add(href)
                    size = self.number(self.child(pkg, ns, "size", href).get("package"), "package-inventory", href)
                    if self.package_hash(href, size) != pkgid:
                        self.fail("package-inventory", "PACKAGE_CHECKSUM_MISMATCH", href)
                else:
                    pkgid, name, arch = pkg.get("pkgid", ""), pkg.get("name"), pkg.get("arch")
                if not SHA256_HEX_RE.fullmatch(pkgid) or pkgid in linked:
                    self.fail("metadata-linkage", "PKGID_MISMATCH")
                values = (name, arch, ver.get("epoch"), ver.get("ver"), ver.get("rel"))
                if any(not isinstance(v, str) or not v or len(v) > 200 for v in values):
                    self.fail("metadata-linkage", "METADATA_LINKAGE_MISMATCH")
                linked[pkgid] = values
            if kind == "primary":
                primary = linked
            elif set(linked) != set(primary):
                self.fail("metadata-linkage", "PKGID_MISMATCH")
            elif linked != primary:
                self.fail("metadata-linkage", "METADATA_LINKAGE_MISMATCH")
        if self.physical_packages() != hrefs:
            self.fail("package-inventory", "PACKAGE_INVENTORY_MISMATCH")
        if expected is not None:
            expected = list(expected)
            if len(expected) > MAX_PACKAGES or len(set(expected)) != len(expected):
                self.fail("package-inventory", "PACKAGE_INVENTORY_MISMATCH")
            if {self.package_href(h) for h in expected} != hrefs:
                self.fail("package-inventory", "PACKAGE_INVENTORY_MISMATCH")
        return {"status": "pass", "operation": "repodata-format-verify", "is_signed": signed,
                "repomd_path": "repodata/repomd.xml", "repomd_sha256": hashlib.sha256(raw).hexdigest(),
                "packages_count": len(hrefs), "verified_packages": sorted(hrefs),
                "data_objects": [{"type": kind, **objects[kind]} for kind in sorted(objects)]}


def verify_repository_metadata(directory, *, expected_packages=None, is_signed=False,
                               receipt=None, max_xml_bytes=1024**2,
                               max_decompressed_bytes=64 * 1024**2):
    """Verify exact core metadata and inventory before signing or readiness claims.

    Package layouts are explicit at production call sites; the direct builder uses
    architecture subdirectories, while native and Pages use Packages/.
    """
    verifier = _Verifier(directory, receipt, max_xml_bytes, max_decompressed_bytes)
    try:
        return verifier.verify(expected_packages, is_signed)
    except OSError:
        verifier.fail("repodata-inventory", "READ_FAILED")
