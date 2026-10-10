"""Test fixtures and helpers for generating coherent, valid gzip RPM repository metadata."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
from pathlib import Path
import re
from typing import Any, Mapping, Sequence


def create_valid_repodata(
    directory: Path | str,
    packages: Sequence[Mapping[str, Any] | Path | str] | None = None,
    *,
    is_signed: bool = False,
    signer: Any = None,
    revision: int = 1700000000,
) -> dict[str, Any]:
    """Create complete, coherent gzip repodata in directory conforming to verifier rules.

    Generates primary.xml.gz, filelists.xml.gz, other.xml.gz, repomd.xml, and optionally
    repomd.xml.asc with matching counts, checksums, open sizes, and package linkage.
    """
    dir_path = Path(directory).resolve()
    repodata_dir = dir_path / "repodata"
    repodata_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(repodata_dir, 0o755)

    pkg_list: list[dict[str, Any]] = []

    if packages is None:
        # Discover existing .rpm files
        found_rpms = sorted(
            p for p in dir_path.rglob("*.rpm")
            if "repodata" not in p.parts and not p.is_symlink()
        )
        for p in found_rpms:
            rel_href = p.relative_to(dir_path).as_posix()
            data = p.read_bytes()
            sha = hashlib.sha256(data).hexdigest()
            size = len(data)
            match = re.match(r"^(.+)-([^-]+)-([^-]+)\.([^.]+)\.rpm$", p.name)
            if match:
                name, ver, rel, arch = match.groups()
            else:
                name, ver, rel, arch = p.stem, "1.0.0", "1.fc43", "noarch"
            pkg_list.append({
                "name": name,
                "arch": arch,
                "version": ver,
                "release": rel,
                "epoch": "0",
                "sha256": sha,
                "size": size,
                "href": rel_href,
            })
    else:
        for item in packages:
            if isinstance(item, (str, Path)):
                p = Path(item)
                if not p.is_absolute():
                    full_path = dir_path / p
                    rel_href = p.as_posix()
                else:
                    full_path = p
                    rel_href = p.relative_to(dir_path).as_posix()
                if not full_path.exists():
                    full_path.parent.mkdir(parents=True, exist_ok=True)
                    content = f"dummy-rpm-content-{p.name}".encode()
                    full_path.write_bytes(content)
                    os.chmod(full_path, 0o644)
                data = full_path.read_bytes()
                sha = hashlib.sha256(data).hexdigest()
                size = len(data)
                match = re.match(r"^(.+)-([^-]+)-([^-]+)\.([^.]+)\.rpm$", full_path.name)
                if match:
                    name, ver, rel, arch = match.groups()
                else:
                    name, ver, rel, arch = full_path.stem, "1.0.0", "1.fc43", "noarch"
                pkg_list.append({
                    "name": name,
                    "arch": arch,
                    "version": ver,
                    "release": rel,
                    "epoch": "0",
                    "sha256": sha,
                    "size": size,
                    "href": rel_href,
                })
            elif isinstance(item, dict):
                rel_href = item.get("href") or f"Packages/{item['name']}-{item['version']}-{item['release']}.{item['arch']}.rpm"
                full_path = dir_path / rel_href
                if "bytes" in item:
                    full_path.parent.mkdir(parents=True, exist_ok=True)
                    full_path.write_bytes(item["bytes"])
                    os.chmod(full_path, 0o644)
                    data = item["bytes"]
                    sha = hashlib.sha256(data).hexdigest()
                    size = len(data)
                elif full_path.exists():
                    data = full_path.read_bytes()
                    sha = hashlib.sha256(data).hexdigest()
                    size = len(data)
                else:
                    full_path.parent.mkdir(parents=True, exist_ok=True)
                    data = f"dummy-content-{item['name']}".encode()
                    full_path.write_bytes(data)
                    os.chmod(full_path, 0o644)
                    sha = hashlib.sha256(data).hexdigest()
                    size = len(data)
                pkg_list.append({
                    "name": item.get("name", "test-pkg"),
                    "arch": item.get("arch", "noarch"),
                    "version": item.get("version", "1.0.0"),
                    "release": item.get("release", "1.fc43"),
                    "epoch": item.get("epoch", "0"),
                    "sha256": item.get("sha256", sha),
                    "size": item.get("size", size),
                    "href": rel_href,
                })

    pkg_count = len(pkg_list)

    # 1. Primary XML
    primary_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>\n',
        f'<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="{pkg_count}">\n'
    ]
    for pkg in pkg_list:
        primary_parts.append(
            f'  <package type="rpm">\n'
            f'    <name>{pkg["name"]}</name>\n'
            f'    <arch>{pkg["arch"]}</arch>\n'
            f'    <version epoch="{pkg["epoch"]}" ver="{pkg["version"]}" rel="{pkg["release"]}"/>\n'
            f'    <checksum type="sha256" pkgid="YES">{pkg["sha256"]}</checksum>\n'
            f'    <summary>Test summary for {pkg["name"]}</summary>\n'
            f'    <description>Test description for {pkg["name"]}</description>\n'
            f'    <packager>Release Starport 9</packager>\n'
            f'    <url>https://example.invalid</url>\n'
            f'    <time file="{revision}" build="{revision}"/>\n'
            f'    <size package="{pkg["size"]}" installed="{pkg["size"]}" archive="{pkg["size"]}"/>\n'
            f'    <location href="{pkg["href"]}"/>\n'
            f'    <format>\n'
            f'      <rpm:license>Apache-2.0</rpm:license>\n'
            f'      <rpm:vendor>Starport</rpm:vendor>\n'
            f'      <rpm:group>Applications</rpm:group>\n'
            f'      <rpm:buildhost>builder.invalid</rpm:buildhost>\n'
            f'      <rpm:sourcerpm>{pkg["name"]}-{pkg["version"]}-{pkg["release"]}.src.rpm</rpm:sourcerpm>\n'
            f'      <rpm:header-range start="0" end="0"/>\n'
            f'      <rpm:provides>\n'
            f'        <rpm:entry name="{pkg["name"]}" flags="EQ" epoch="{pkg["epoch"]}" ver="{pkg["version"]}" rel="{pkg["release"]}"/>\n'
            f'      </rpm:provides>\n'
            f'    </format>\n'
            f'  </package>\n'
        )
    primary_parts.append('</metadata>\n')
    primary_xml = "".join(primary_parts).encode("utf-8")

    # 2. Filelists XML
    filelists_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>\n',
        f'<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="{pkg_count}">\n'
    ]
    for pkg in pkg_list:
        filelists_parts.append(
            f'  <package pkgid="{pkg["sha256"]}" name="{pkg["name"]}" arch="{pkg["arch"]}">\n'
            f'    <version epoch="{pkg["epoch"]}" ver="{pkg["version"]}" rel="{pkg["release"]}"/>\n'
            f'    <file>/usr/bin/{pkg["name"]}</file>\n'
            f'  </package>\n'
        )
    filelists_parts.append('</filelists>\n')
    filelists_xml = "".join(filelists_parts).encode("utf-8")

    # 3. Other XML
    other_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>\n',
        f'<otherdata xmlns="http://linux.duke.edu/metadata/other" packages="{pkg_count}">\n'
    ]
    for pkg in pkg_list:
        other_parts.append(
            f'  <package pkgid="{pkg["sha256"]}" name="{pkg["name"]}" arch="{pkg["arch"]}">\n'
            f'    <version epoch="{pkg["epoch"]}" ver="{pkg["version"]}" rel="{pkg["release"]}"/>\n'
            f'    <changelog author="Maintainer &lt;pkg@starport.invalid&gt;" date="{revision}">- Release {pkg["version"]}</changelog>\n'
            f'  </package>\n'
        )
    other_parts.append('</otherdata>\n')
    other_xml = "".join(other_parts).encode("utf-8")

    # Clean existing repodata contents (remove old xml/gz/asc/zst files)
    for existing in repodata_dir.iterdir():
        if existing.is_file():
            existing.unlink()

    meta_files: dict[str, dict[str, Any]] = {}
    for type_name, xml_data in [("primary", primary_xml), ("filelists", filelists_xml), ("other", other_xml)]:
        open_sha = hashlib.sha256(xml_data).hexdigest()
        open_size = len(xml_data)

        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
            gz.write(xml_data)
        comp_bytes = buf.getvalue()
        comp_sha = hashlib.sha256(comp_bytes).hexdigest()
        comp_size = len(comp_bytes)

        rel_href = f"repodata/{comp_sha}-{type_name}.xml.gz"
        out_file = dir_path / rel_href
        out_file.write_bytes(comp_bytes)
        os.chmod(out_file, 0o644)

        meta_files[type_name] = {
            "href": rel_href,
            "sha256": comp_sha,
            "size": comp_size,
            "open_sha256": open_sha,
            "open_size": open_size,
        }

    # 4. repomd.xml
    repomd_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>\n',
        '<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">\n',
        f'  <revision>{revision}</revision>\n',
    ]
    for type_name in ["primary", "filelists", "other"]:
        m = meta_files[type_name]
        repomd_parts.append(
            f'  <data type="{type_name}">\n'
            f'    <checksum type="sha256">{m["sha256"]}</checksum>\n'
            f'    <open-checksum type="sha256">{m["open_sha256"]}</open-checksum>\n'
            f'    <location href="{m["href"]}"/>\n'
            f'    <timestamp>{revision}</timestamp>\n'
            f'    <size>{m["size"]}</size>\n'
            f'    <open-size>{m["open_size"]}</open-size>\n'
            f'  </data>\n'
        )
    repomd_parts.append('</repomd>\n')
    repomd_bytes = "".join(repomd_parts).encode("utf-8")
    repomd_file = repodata_dir / "repomd.xml"
    repomd_file.write_bytes(repomd_bytes)
    os.chmod(repomd_file, 0o644)

    sig_file = None
    if is_signed and signer is not None:
        sig_bytes = signer.detach_sign(repomd_bytes, armor=True)
        sig_file = repodata_dir / "repomd.xml.asc"
        sig_file.write_bytes(sig_bytes)
        os.chmod(sig_file, 0o644)

    return {
        "repomd_path": repomd_file,
        "repomd_bytes": repomd_bytes,
        "data_files": meta_files,
        "signature_path": sig_file,
        "packages": pkg_list,
    }
