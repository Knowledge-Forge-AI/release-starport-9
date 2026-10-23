"""Python package artifact verification for APGR: wheels, sdist, RECORD, ELF and Mach-O."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import re
import tarfile
import zipfile
from typing import Any, Mapping

from rs9.macho import parse_macho_arm64
from rs9.elf import parse_elf
from rs9.errors import ContractError
from rs9.security import validate_safe_relative_posix_path

def _record_digest(data: bytes) -> str:
    """Format base64 sha256 digest for PEP 376 RECORD."""
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")


def normalize_project_name(name: str) -> str:
    """Normalize Python project distribution name per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_rfc822_headers(content: bytes) -> dict[str, str]:
    """Parse RFC 822 key-value headers from METADATA or PKG-INFO."""
    headers: dict[str, str] = {}
    lines = content.decode("utf-8", errors="replace").splitlines()
    for line in lines:
        if not line.strip():
            break  # End of header section
        if ":" in line and not line.startswith((" ", "\t")):
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def check_requires_python(specifier: str, version: tuple[int, ...] = (3, 12)) -> bool:
    """Evaluate the bounded numeric Requires-Python grammar; unsupported syntax stops."""
    if not specifier:
        return True
    accepted = True
    for clause in specifier.split(","):
        match = re.fullmatch(r"\s*(>=|<=|==|!=|~=|>|<)\s*([0-9]+(?:\.[0-9]+)*)(\.\*)?\s*", clause)
        if not match:
            raise ContractError("APGR7_PYTHON_SPECIFIER", "Unparsed Requires-Python clause")
        op, text, wildcard = match.groups()
        parts = tuple(map(int, text.split(".")))
        if wildcard and op not in ("==", "!=") or op == "~=" and len(parts) < 2:
            raise ContractError("APGR7_PYTHON_SPECIFIER", "Unsupported Requires-Python operator/version")
        length = max(len(version), len(parts))
        actual, required = version + (0,) * (length - len(version)), parts + (0,) * (length - len(parts))
        equal = version[:len(parts)] == parts if wildcard else actual == required
        value = {">=": actual >= required, "<=": actual <= required, ">": actual > required, "<": actual < required,
                 "==": equal, "!=": not equal, "~=": actual >= required and actual[:len(parts)-1] == required[:len(parts)-1]}[op]
        accepted = accepted and value
    return accepted


def verify_requires_python(metadata: Mapping[str, str], version: tuple[int, ...] = (3, 12)) -> bool:
    """Verify that metadata Requires-Python admits target runtime version (e.g. 3.12)."""
    spec = metadata.get("Requires-Python")
    if spec and not check_requires_python(spec, version):
        ver_str = ".".join(str(p) for p in version)
        raise ContractError(
            "APGR7_PYTHON_COMPATIBILITY",
            f"Requires-Python '{spec}' is not compatible with required runtime {ver_str}",
        )
    return True


def assess_sdist_fallback(
    artifacts: list[dict[str, Any]],
    excluded: list[dict[str, Any]],
    sdist_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assess sdist fallback consequences when binary wheels are excluded or unavailable."""
    wheel_tags = [a["tag"] for a in artifacts if a.get("kind") == "wheel" and a.get("tag")]
    excluded_names = [e["name"] for e in excluded]
    has_sdist = any(a.get("kind") == "sdist" or a.get("name", "").endswith((".tar.gz", ".tgz")) for a in artifacts)
    excluded_note = " (including excluded macOS arm64)" if excluded_names else ""
    consequences = [
        f"Clients on platforms without pre-compiled wheels{excluded_note} fall back to sdist installation",
        "Sdist installation has not been executed on macOS; build backend requirements and failure mode remain unqualified",
        "Runtime Python compatibility requires Requires-Python to include target runtimes such as Python 3.12",
        "Other distribution routes require their own independent publication and native installation readbacks",
    ]
    return {
        "wheel_platforms": wheel_tags,
        "excluded_artifacts": excluded_names,
        "has_sdist": has_sdist,
        "requires_python_312": all(a.get("python_compatibility", {}).get("3.12", False) for a in artifacts),
        "macos_sdist_installation": "not-run",
        "consequences": consequences,
    }


def parse_elf_native(data: bytes, expected_machine: str) -> dict[str, Any]:
    """Validate ELF binary using rs9.elf.parse_elf and enforce manylinux glibc floor."""
    info = parse_elf(data)
    if info.get("machine") != expected_machine:
        raise ContractError(
            "APGR7_PYTHON_ELF",
            f"ELF machine mismatch: expected {expected_machine}, got {info.get('machine')}",
        )

    # manylinux_2_17 requires all GLIBC version requirements to be <= 2.17.
    # Static binaries (no needed libraries or empty version_needs) satisfy this.
    for lib, versions in info.get("version_needs", {}).items():
        for ver in versions:
            if ver.startswith("GLIBC_"):
                parts = ver[len("GLIBC_") :].split(".")
                try:
                    ver_tuple = tuple(int(p) for p in parts)
                    if ver_tuple > (2, 17):
                        raise ContractError(
                            "APGR7_PYTHON_GLIBC",
                            f"GLIBC symbol requirement {ver} in {lib} exceeds manylinux_2_17 ceiling",
                        )
                except ValueError:
                    raise ContractError("APGR7_PYTHON_GLIBC", "Unrecognized required GLIBC version") from None

    return info


def verify_wheel_record(zf: zipfile.ZipFile, dist_info_dir: str) -> None:
    """Strict bidirectional verification between ZIP archive members and PEP 376 RECORD."""
    record_path = f"{dist_info_dir}/RECORD"
    namelist = zf.namelist()
    if record_path not in namelist:
        raise ContractError("APGR7_PYTHON_RECORD", f"Missing {record_path} in wheel")

    record_bytes = zf.read(record_path)
    try:
        record_text = record_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ContractError("APGR7_PYTHON_RECORD", "RECORD file is not valid UTF-8")

    rec_rows = list(csv.reader(record_text.splitlines()))
    rec_map: dict[str, tuple[str, int]] = {}
    for row in rec_rows:
        if not row:
            continue
        if len(row) != 3:
            raise ContractError("APGR7_PYTHON_RECORD", f"Invalid RECORD row: {row}")
        fn, h, sz = row[0], row[1], row[2]
        if fn in rec_map:
            raise ContractError("APGR7_PYTHON_RECORD", f"Duplicate entry in RECORD: {fn}")
        if fn == record_path:
            if h != "" or sz != "":
                raise ContractError(
                    "APGR7_PYTHON_RECORD",
                    "RECORD entry for RECORD itself must have empty hash and size",
                )
            rec_map[fn] = ("", 0)
        else:
            try:
                rec_map[fn] = (h, int(sz))
            except ValueError:
                raise ContractError("APGR7_PYTHON_RECORD", f"Non-integer size in RECORD for {fn}: {sz}")

    if record_path not in rec_map:
        raise ContractError("APGR7_PYTHON_RECORD", "RECORD must contain an entry for itself")

    # Bidirectional verification: all zip files must match RECORD entries
    zip_files = set(namelist)
    record_files = set(rec_map.keys())

    if zip_files != record_files:
        extra_zip = zip_files - record_files
        missing_zip = record_files - zip_files
        raise ContractError(
            "APGR7_PYTHON_RECORD",
            f"RECORD bidirectional mismatch (extra_zip={extra_zip}, missing_zip={missing_zip})",
        )

    for fn in namelist:
        if fn == record_path:
            continue
        member_bytes = zf.read(fn)
        expected_digest, expected_size = rec_map[fn]
        if len(member_bytes) != expected_size:
            raise ContractError(
                "APGR7_PYTHON_RECORD",
                f"Size mismatch for {fn}: zip={len(member_bytes)}, RECORD={expected_size}",
            )
        actual_digest = _record_digest(member_bytes)
        if actual_digest != expected_digest:
            raise ContractError(
                "APGR7_PYTHON_RECORD",
                f"Digest mismatch for {fn}: zip={actual_digest}, RECORD={expected_digest}",
            )


def _wheel_metadata(zf, dist_info_dir, expected_project, expected_version, expected_license, expected_tag):
    metadata_bytes = zf.read(f"{dist_info_dir}/METADATA")
    metadata = parse_rfc822_headers(metadata_bytes)

    if normalize_project_name(metadata.get("Name", "")) != normalize_project_name(expected_project):
        raise ContractError(
            "APGR7_PYTHON_IDENTITY",
            f"Wheel METADATA Name '{metadata.get('Name')}' does not match expected '{expected_project}'",
        )
    if metadata.get("Version") != expected_version:
        raise ContractError(
            "APGR7_PYTHON_IDENTITY",
            f"Wheel METADATA Version '{metadata.get('Version')}' does not match expected '{expected_version}'",
        )
    if metadata.get("License-Expression") != expected_license:
        raise ContractError(
            "APGR7_PYTHON_IDENTITY",
            f"Wheel METADATA License-Expression '{metadata.get('License-Expression')}' does not match expected '{expected_license}'",
        )

    wheel_bytes = zf.read(f"{dist_info_dir}/WHEEL")
    wheel_headers = parse_rfc822_headers(wheel_bytes)
    if wheel_headers.get("Wheel-Version") != "1.0":
        raise ContractError("APGR7_PYTHON_METADATA", "Wheel-Version must be 1.0")
    if wheel_headers.get("Root-Is-Purelib") != "false":
        raise ContractError("APGR7_PYTHON_METADATA", "Root-Is-Purelib must be false for native wheels")
    if wheel_headers.get("Tag") != expected_tag:
        raise ContractError(
            "APGR7_PYTHON_METADATA",
            f"WHEEL Tag '{wheel_headers.get('Tag')}' does not match filename tag '{expected_tag}'",
        )

    verify_requires_python(metadata, (3, 12))
    return metadata


def _wheel_native(zf, namelist, expected_tag):
    # Embedded native binary verification: agentic_praxis_grimoire/bin/apgr
    bin_path = "agentic_praxis_grimoire/bin/apgr"
    if bin_path not in namelist:
        raise ContractError("APGR7_PYTHON_NATIVE", f"Missing native binary {bin_path} in wheel")

    bin_data = zf.read(bin_path)
    if "manylinux_2_17_x86_64" in expected_tag:
        parse_elf_native(bin_data, "x86_64")
    elif "manylinux_2_17_aarch64" in expected_tag:
        parse_elf_native(bin_data, "aarch64")
    elif expected_tag in {"py3-none-macosx_11_0_arm64", "py3-none-macosx_12_0_arm64"}:
        macho_info = parse_macho_arm64(bin_data)
        major, minor = macho_info["deployment_minimum"]
        deployment_minimum = (major, minor)
        if expected_tag == "py3-none-macosx_11_0_arm64":
            # Preserve the historical v0.13.0 contract: the 11.0 wheel may
            # target an earlier Darwin minimum, but never a newer one.
            if deployment_minimum > (11, 0):
                raise ContractError(
                    "APGR7_PYTHON_MACHO",
                    f"Mach-O deployment minimum {deployment_minimum} exceeds macOS 11.0 wheel ceiling",
                )
        elif deployment_minimum != (12, 0):
            # The v0.13.1 Darwin artifact is deliberately exact: its wheel
            # floor and native deployment minimum must both be macOS 12.0.
            raise ContractError(
                "APGR7_PYTHON_MACHO",
                f"Mach-O deployment minimum {deployment_minimum} does not equal macOS 12.0 wheel floor",
            )


def verify_wheel(
    name: str,
    body: bytes,
    *,
    expected_project: str,
    expected_version: str,
    expected_license: str,
) -> dict[str, Any]:
    """Verify an APGR upstream wheel: structure, metadata, RECORD, native binary."""
    if not name.endswith(".whl"):
        raise ContractError("APGR7_PYTHON_ARTIFACT", f"Expected wheel filename, got {name}")

    # Extract wheel filename tags: {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl
    base = name[:-4]
    parts = base.split("-")
    if len(parts) < 5:
        raise ContractError("APGR7_PYTHON_ARTIFACT", f"Invalid wheel filename format: {name}")

    dist_name, dist_ver = parts[0], parts[1]
    expected_tag = "-".join(parts[-3:])
    if normalize_project_name(dist_name) != normalize_project_name(expected_project) or dist_ver != expected_version:
        raise ContractError("APGR7_PYTHON_IDENTITY", "Wheel filename identity differs")
    versioned_tags = {
        "0.13.0": "py3-none-macosx_11_0_arm64",
        "0.13.1": "py3-none-macosx_12_0_arm64",
    }
    allowed_tags = {
        "py3-none-manylinux_2_17_x86_64",
        "py3-none-manylinux_2_17_aarch64",
    }
    darwin_tag = versioned_tags.get(expected_version)
    if darwin_tag:
        allowed_tags.add(darwin_tag)
    if expected_tag not in allowed_tags:
        raise ContractError("APGR7_PYTHON_METADATA", "Unselected wheel platform")

    with zipfile.ZipFile(io.BytesIO(body), "r") as zf:
        members = zf.infolist()
        if len(members) > 2048 or sum(m.file_size for m in members) > 64 * 1024 * 1024:
            raise ContractError("APGR7_PYTHON_BOUNDS", "Wheel exceeds archive size or member limits")

        namelist = zf.namelist()
        if len(namelist) != len(set(namelist)):
            raise ContractError("APGR7_PYTHON_ARCHIVE", "Duplicate members in wheel archive")

        for member in members:
            if (member.external_attr >> 16) & 0o170000 == 0o120000 or member.flag_bits & 1:
                raise ContractError("APGR7_PYTHON_ARCHIVE", "Encrypted or linked wheel member")
        for fn in namelist:
            validate_safe_relative_posix_path(fn)

        dist_info_dir = next(
            (p.split("/")[0] for p in sorted(set(namelist)) if p.endswith(".dist-info/METADATA")),
            None,
        )
        if not dist_info_dir:
            raise ContractError("APGR7_PYTHON_METADATA", f"Missing .dist-info/METADATA in wheel {name}")

        metadata = _wheel_metadata(zf, dist_info_dir, expected_project, expected_version, expected_license, expected_tag)

        # RECORD verification: strict bidirectional matching
        verify_wheel_record(zf, dist_info_dir)

        _wheel_native(zf, namelist, expected_tag)

    return {
        "name": name,
        "kind": "wheel",
        "tag": expected_tag,
        "size": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "metadata": metadata,
    }


def verify_sdist(
    name: str,
    body: bytes,
    *,
    expected_project: str,
    expected_version: str,
    expected_license: str,
) -> dict[str, Any]:
    """Verify an APGR upstream sdist: structure and PKG-INFO metadata."""
    if not (name.endswith(".tar.gz") or name.endswith(".tgz")):
        raise ContractError("APGR7_PYTHON_ARTIFACT", f"Expected sdist tar.gz filename, got {name}")

    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tf:
        members = tf.getmembers()
        if len(members) > 2048 or sum(m.size for m in members) > 64 * 1024 * 1024:
            raise ContractError("APGR7_PYTHON_BOUNDS", "Sdist exceeds archive size or member limits")

        names = set()
        for member in members:
            validate_safe_relative_posix_path(member.name)
            if member.name in names or not (member.isfile() or member.isdir()):
                raise ContractError("APGR7_PYTHON_ARCHIVE", "Duplicate, linked or special sdist member")
            names.add(member.name)

        # Locate PKG-INFO in root directory
        expected_root = name.replace(".tar.gz", "").replace(".tgz", "")
        pkg_info_name = f"{expected_root}/PKG-INFO"
        if pkg_info_name not in names:
            # Fallback search for any PKG-INFO
            pkg_info_name = next((n for n in names if n.endswith("/PKG-INFO")), None)

        if not pkg_info_name:
            raise ContractError("APGR7_PYTHON_METADATA", "Missing PKG-INFO in sdist archive")

        extracted = tf.extractfile(pkg_info_name)
        if extracted is None:
            raise ContractError("APGR7_PYTHON_METADATA", "Unable to extract PKG-INFO from sdist")

        metadata = parse_rfc822_headers(extracted.read())

        if normalize_project_name(metadata.get("Name", "")) != normalize_project_name(expected_project):
            raise ContractError(
                "APGR7_PYTHON_IDENTITY",
                f"Sdist PKG-INFO Name '{metadata.get('Name')}' does not match expected '{expected_project}'",
            )
        if metadata.get("Version") != expected_version:
            raise ContractError(
                "APGR7_PYTHON_IDENTITY",
                f"Sdist PKG-INFO Version '{metadata.get('Version')}' does not match expected '{expected_version}'",
            )
        if metadata.get("License-Expression") != expected_license:
            raise ContractError(
                "APGR7_PYTHON_IDENTITY",
                f"Sdist PKG-INFO License-Expression '{metadata.get('License-Expression')}' does not match expected '{expected_license}'",
            )

        verify_requires_python(metadata, (3, 12))

    return {
        "name": name,
        "kind": "sdist",
        "tag": None,
        "size": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "metadata": metadata,
    }


def verify_artifact(
    name: str,
    body: bytes,
    *,
    expected_project: str,
    expected_version: str,
    expected_license: str,
) -> dict[str, Any]:
    """Verify either a wheel or sdist artifact."""
    if name.endswith(".whl"):
        return verify_wheel(
            name,
            body,
            expected_project=expected_project,
            expected_version=expected_version,
            expected_license=expected_license,
        )
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        return verify_sdist(
            name,
            body,
            expected_project=expected_project,
            expected_version=expected_version,
            expected_license=expected_license,
        )
    raise ContractError("APGR7_PYTHON_ARTIFACT", f"Unknown Python release artifact type: {name}")
