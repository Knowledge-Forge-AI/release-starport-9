"""Shared package role definitions, producer retention classification, and verification.

Defines explicit package roles:
- binary-package: installable candidate package built for target architecture
- source-package-evidence: retained source RPM evidence for reproducibility
- fixture-signed-copy: signed copy used only for fixture client testing
- unclassified-package: unrecognized or unauthorized package role (fails closed)
"""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
import struct
from typing import Any, Mapping

from rs9.errors import ContractError
from rs9.rpm_header import RPM_LEAD_MAGIC, RPM_HEADER_MAGIC, parse_header
from rs9.security import validate_safe_relative_posix_path
from rs9.product_classes import extract_package_arch

BINARY_PACKAGE: str = "binary-package"
SOURCE_PACKAGE_EVIDENCE: str = "source-package-evidence"
FIXTURE_SIGNED_COPY: str = "fixture-signed-copy"
UNCLASSIFIED_PACKAGE: str = "unclassified-package"

ALL_ROLES: frozenset[str] = frozenset({
    BINARY_PACKAGE,
    SOURCE_PACKAGE_EVIDENCE,
    FIXTURE_SIGNED_COPY,
    UNCLASSIFIED_PACKAGE,
})

VALID_PRODUCER_ROLES: frozenset[str] = frozenset({
    BINARY_PACKAGE,
    SOURCE_PACKAGE_EVIDENCE,
    FIXTURE_SIGNED_COPY,
})

PACKAGE_EXTENSIONS: tuple[str, ...] = (
    ".whl",
    ".rpm",
    ".deb",
    ".pkg.tar.zst",
    ".pkg.tar.xz",
)


def _normalize_posix_path(relative_path: str | Path) -> str:
    posix = Path(relative_path).as_posix()
    if posix.startswith("objects/"):
        posix = posix[len("objects/"):]
    return posix


def _is_pinned_source_rpm_path(posix: str) -> bool:
    """Pin source producer path lane-work/unsigned-source/<name>.src.rpm (manifest objects/ prefix)."""
    parts = Path(posix).parts
    if len(parts) == 3 and parts[0] == "lane-work" and parts[1] == "unsigned-source":
        return parts[2].endswith(".src.rpm")
    return False


def producer_role(lane: str, relative_path: str | Path) -> str:
    """Classify producer package role from lane and relative path. Unknown roles fail closed."""
    if lane not in {"rpm", "deb", "pacman", "wheels", "pages"}:
        return UNCLASSIFIED_PACKAGE

    posix = _normalize_posix_path(relative_path)
    if not any(posix.endswith(ext) for ext in PACKAGE_EXTENSIONS):
        return UNCLASSIFIED_PACKAGE

    if lane != "pages" and not posix.endswith({"rpm": (".rpm",), "deb": (".deb",),
            "wheels": (".whl",), "pacman": (".pkg.tar.zst", ".pkg.tar.xz")}[lane]):
        return UNCLASSIFIED_PACKAGE

    # Pinned source RPM path in RPM lane
    if posix.endswith((".src.rpm", ".nosrc.rpm")):
        if lane == "rpm" and _is_pinned_source_rpm_path(posix):
            return SOURCE_PACKAGE_EVIDENCE
        return UNCLASSIFIED_PACKAGE

    # In RPM lane, anything in unsigned-source that is not .src.rpm is unclassified
    if lane == "rpm" and ("unsigned-source" in Path(posix).parts):
        return UNCLASSIFIED_PACKAGE

    # These producer directories hold unsigned candidate bytes, including
    # construction-verified packages retained after a later build-stage failure.
    parts = Path(posix).parts
    if len(parts) > 1 and lane in {"rpm", "pacman", "pages"}:
        candidate_directories = {"unsigned", "unsigned-custody", "custody", "custody-deb", "quarantine"}
        if not candidate_directories.intersection(parts[:-1]):
            return FIXTURE_SIGNED_COPY

    # Binary packages in unsigned or custody directories, or bare package filenames
    if lane in {"rpm", "deb", "pacman", "wheels", "pages"}:
        return BINARY_PACKAGE

    return UNCLASSIFIED_PACKAGE


def effective_role(lane: str, row: Mapping[str, Any]) -> str:
    """Historical diagnostic-only role resolver; never upgrades historical authority."""
    if not isinstance(row, (dict, Mapping)):
        return UNCLASSIFIED_PACKAGE

    declared = row.get("role")
    if declared is not None:
        return declared if declared in ALL_ROLES else UNCLASSIFIED_PACKAGE

    # Historical manifest row without role: infer for diagnostics only
    if row.get("kind") != "custody":
        return UNCLASSIFIED_PACKAGE

    if row.get("promotion") == "fixture-test-only":
        return FIXTURE_SIGNED_COPY

    return producer_role(lane, row.get("path", ""))


def is_installable_binary(row: Mapping[str, Any]) -> bool:
    """Explicit verified role, custody and nonfixture predicate for installable binaries."""
    if not isinstance(row, (dict, Mapping)):
        return False
    if row.get("kind") != "custody":
        return False
    if row.get("role") != BINARY_PACKAGE:
        return False
    if row.get("promotion") not in {"candidate-only", "candidate-policy-pending"}:
        return False
    path = row.get("path", "")
    if not isinstance(path, str) or not path.endswith(PACKAGE_EXTENSIONS) or path.endswith((".src.rpm", ".nosrc.rpm")):
        return False
    return True


def _read_bounded_rpm_headers(path: Path) -> tuple[int, dict[int, dict[str, Any]]]:
    """Read RPM lead and signature/main header from bounded prefix, not entire payload."""
    try:
        with open(path, "rb") as f:
            lead = f.read(96)
            if len(lead) < 96 or lead[:4] != RPM_LEAD_MAGIC or lead[4] not in (3, 4):
                raise ContractError("CUSTODY_ROLE", f"Invalid RPM lead magic in {path.name}")
            lead_type = struct.unpack_from(">H", lead, 6)[0]

            sig_magic = f.read(16)
            if len(sig_magic) < 16 or sig_magic[:4] != RPM_HEADER_MAGIC:
                raise ContractError("CUSTODY_ROLE", f"Invalid RPM signature header magic in {path.name}")
            sig_count, sig_size = struct.unpack_from(">II", sig_magic, 8)
            if sig_count > 20000 or sig_size > 1024 * 1024:
                raise ContractError("CUSTODY_ROLE", f"RPM signature header exceeds bound in {path.name}")
            sig_len = 16 * sig_count + sig_size
            sig_body = f.read(sig_len)
            if len(sig_body) < sig_len:
                raise ContractError("CUSTODY_ROLE", f"Truncated RPM signature header in {path.name}")

            sig_end = 96 + 16 + sig_len
            main_offset = (sig_end + 7) & ~7
            padding_len = main_offset - sig_end
            if padding_len > 0:
                pad = f.read(padding_len)
                if len(pad) < padding_len:
                    raise ContractError("CUSTODY_ROLE", f"Truncated RPM padding in {path.name}")

            main_magic = f.read(16)
            if len(main_magic) < 16 or main_magic[:4] != RPM_HEADER_MAGIC:
                raise ContractError("CUSTODY_ROLE", f"Invalid RPM main header magic in {path.name}")
            main_count, main_size = struct.unpack_from(">II", main_magic, 8)
            if main_count > 20000 or main_size > 1024 * 1024:
                raise ContractError("CUSTODY_ROLE", f"RPM main header exceeds bound in {path.name}")
            main_len = 16 * main_count + main_size
            main_body = f.read(main_len)
            if len(main_body) < main_len:
                raise ContractError("CUSTODY_ROLE", f"Truncated RPM main header in {path.name}")

        parse_header(sig_magic + sig_body, 0)
        tags, _ = parse_header(main_magic + main_body, 0)
        return lead_type, tags
    except (ValueError, OSError) as exc:
        raise ContractError("CUSTODY_ROLE", "Failed to inspect bounded RPM headers") from exc


def verify_rpm_package_role(path, role):
    """Validate actual RPM type against a role from an authenticated producer."""
    path = Path(path)
    lead_type, tags = _read_bounded_rpm_headers(path)
    source_marker = tags.get(1106)
    is_source = bool(source_marker and source_marker.get("type") == 4
                     and source_marker.get("count") == 1 and source_marker.get("value") == [1])
    arch_tag = tags.get(1022, {})
    arch = arch_tag.get("value")
    if (arch_tag.get("type") != 6 or not isinstance(arch, list)
            or len(arch) != 1 or not isinstance(arch[0], str)):
        raise ContractError("CUSTODY_ROLE", "Typed RPM architecture header required")
    if role == SOURCE_PACKAGE_EVIDENCE:
        if lead_type != 1 or not is_source or 1044 in tags:
            raise ContractError("CUSTODY_ROLE", "Source RPM type contradicts producer role")
    elif role in {BINARY_PACKAGE, FIXTURE_SIGNED_COPY}:
        if lead_type != 0 or source_marker is not None:
            raise ContractError("CUSTODY_ROLE", "Binary RPM type contradicts producer role")
        if arch[0] not in {"x86_64", "aarch64", "noarch"} or arch[0] != extract_package_arch(path.name):
            raise ContractError("CUSTODY_ARCHITECTURE", "RPM header and binary filename architecture disagree")
    else:
        raise ContractError("CUSTODY_ROLE", "Known producer RPM role required")


def validate_role_declarations(manifest):
    """Shared metadata check, also usable when a summary has no package bytes."""
    files = manifest.get("files", [])
    if not isinstance(files, list) or any(not isinstance(row, dict) for row in files):
        raise ContractError("CUSTODY_ROLE", "Typed manifest file rows required")
    result = {}
    for row in files:
        path = row.get("path")
        validate_safe_relative_posix_path(path)
        if row.get("kind") != "custody":
            continue
        role = row.get("role")
        if role not in VALID_PRODUCER_ROLES or role != producer_role(manifest.get("lane"), path):
            raise ContractError("CUSTODY_ROLE", "Explicit producer package role required")
        allowed = {"fixture-test-only"} if role == FIXTURE_SIGNED_COPY else {"candidate-only", "candidate-policy-pending"}
        if row.get("promotion") not in allowed:
            raise ContractError("CUSTODY_ROLE", "Package role and promotion scope disagree")
        result[path] = role
    return result


def verify_package_roles(directory: Path | str, manifest: dict[str, Any]) -> dict[str, Any]:
    """Verify producer/type agreement and every source object's reproducibility binding.

    SOURCEPACKAGE and the lead identify source RPMs. Their ARCH describes the
    build target, and is not the filename's synthetic src architecture.
    """
    directory = Path(directory)
    lane = manifest.get("lane")
    files = manifest.get("files", [])
    verified_roles = validate_role_declarations(manifest)
    source_rows, declarations = {}, {}

    for row in files:
        if row.get("kind") != "custody":
            continue
        path = row["path"]
        role = verified_roles[path]
        target = directory / path
        if target.is_symlink() or not target.is_file():
            raise ContractError("CUSTODY_ROLE", "Physical package object required")
        if target.name.endswith(".rpm"):
            verify_rpm_package_role(target, role)
            if role == SOURCE_PACKAGE_EVIDENCE:
                name = target.name
                if name in source_rows:
                    raise ContractError("CUSTODY_SOURCE_EVIDENCE", "Duplicate source object")
                source_rows[name] = row
        verified_roles[path] = role

    if lane == "rpm":
        for row in files:
            if Path(row["path"]).name != "rpm-manifest.json":
                continue
            target = directory / row["path"]
            try:
                if target.is_symlink() or not target.is_file() or target.stat().st_size > 512 * 1024:
                    raise ValueError()
                build = json.loads(target.read_bytes())
                if not isinstance(build, dict):
                    raise ValueError()
                # Current producer shape is top-level reproducibility. Witness
                # and derivation copies must agree when they carry the same data.
                witness = build.get("construction_witness", {})
                derivation = build.get("derivation", {})
                if not isinstance(witness, dict) or not isinstance(derivation, dict):
                    raise ValueError()
                evidence = derivation.get("evidence", {})
                if not isinstance(evidence, dict):
                    raise ValueError()
                copies = [owner["reproducibility"] for owner in (build, witness, evidence)
                          if "reproducibility" in owner]
                if not copies:
                    continue
                if any(not isinstance(repro, dict) for repro in copies):
                    raise ValueError()
                refs = [repro.get("source_rpm") for repro in copies]
                ref = refs[0]
                if any(item != ref for item in refs) or not isinstance(ref, dict):
                    raise ValueError()
                name, digest, size = ref.get("name"), ref.get("sha256"), ref.get("size")
                if (not isinstance(name, str) or Path(name).name != name or not name.endswith(".src.rpm")
                        or not isinstance(digest, str) or len(digest) != 64
                        or any(c not in "0123456789abcdef" for c in digest)
                        or type(size) is not int or size <= 0 or name in declarations):
                    raise ValueError()
                product = build.get("project")
                if not isinstance(product, str) or not name.startswith(product + "-"):
                    raise ValueError()
                declarations[name] = ref
            except (OSError, ValueError, KeyError, TypeError):
                raise ContractError("CUSTODY_SOURCE_EVIDENCE", "Malformed source reproducibility declaration") from None
    if set(source_rows) != set(declarations):
        raise ContractError("CUSTODY_SOURCE_EVIDENCE", "Exact declared source evidence set required")
    for name, row in source_rows.items():
        ref = declarations[name]
        target = directory / row["path"]
        with target.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if (row.get("sha256") != ref["sha256"] or row.get("size") != ref["size"]
                or target.stat().st_size != ref["size"] or actual != ref["sha256"]):
            raise ContractError("CUSTODY_SOURCE_EVIDENCE", "Source object differs from reproducibility binding")
    return {"verified_roles": verified_roles, "declared_sources": declarations}
