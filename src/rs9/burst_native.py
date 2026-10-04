"""Native prebuild inspection, qualification, and provenance contracts for Stellar Burst."""
from __future__ import annotations

import json
import re
import struct
import types
from typing import Any, Mapping

from rs9.errors import ContractError
from rs9.build_native import is_native_payload
from rs9.hosted_platforms import SUPPORTED_WHEEL_SYSTEMS, platform_contract
from rs9.release_core import digest

BURST_PRODUCT_ID: str = "theme-forge-stellar-burst"
BURST_BACKEND_NAME: str = "native-addon-posix-openat-v1"
BURST_PREBUILD_SUBDIR: str = "package/native/directory-snapshot/prebuilds"

# Exactly closed prebuild paths admitted from release origin
_RAW_BURST_CLOSED_PREBUILDS: dict[str, str] = {
    "darwin-arm64": f"{BURST_PREBUILD_SUBDIR}/darwin-arm64/{BURST_BACKEND_NAME}.node",
    "darwin-x64": f"{BURST_PREBUILD_SUBDIR}/darwin-x64/{BURST_BACKEND_NAME}.node",
    "linux-arm64-gnu": f"{BURST_PREBUILD_SUBDIR}/linux-arm64-gnu/{BURST_BACKEND_NAME}.node",
    "linux-x64-gnu": f"{BURST_PREBUILD_SUBDIR}/linux-x64-gnu/{BURST_BACKEND_NAME}.node",
}

BURST_CLOSED_PREBUILDS: Mapping[str, str] = types.MappingProxyType(_RAW_BURST_CLOSED_PREBUILDS)
BURST_CLOSED_PREBUILD_PATHS: frozenset[str] = frozenset(_RAW_BURST_CLOSED_PREBUILDS.values())

BURST_SYSTEM_TO_PREBUILD_KEY: Mapping[str, str] = types.MappingProxyType({
    "aarch64-darwin": "darwin-arm64",
    "x86_64-linux": "linux-x64-gnu",
    "aarch64-linux": "linux-arm64-gnu",
})

# Mach-O and ELF constants
_MACHO_MAGIC_64_LE = 0xfeedfacf  # b"\xcf\xfa\xed\xfe"
_MACHO_MAGIC_64_BE = 0xcffaedfe  # b"\xfe\xed\xfa\xcf"
_MACHO_MAGIC_32_LE = 0xfeedface  # b"\xce\xfa\xed\xfe"
_MACHO_MAGIC_32_BE = 0xcefaedfe  # b"\xfe\xed\xfa\xce"
_MACHO_FAT_MAGICS = (0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca)

_CPU_TYPE_X86_64 = 0x01000007
_CPU_TYPE_ARM64 = 0x0100000c

_LC_BUILD_VERSION = 0x32
_LC_VERSION_MIN_MACOSX = 0x24
_PLATFORM_MACOS = 1

_ELF_MAGIC = b"\x7fELF"
_ELFCLASS64 = 2
_ELFDATA2LSB = 1
_EM_X86_64 = 62
_EM_AARCH64 = 183


def inspect_elf_binary(data: bytes) -> dict[str, Any]:
    """Inspect and validate an ELF64 little-endian binary header."""
    if len(data) < 64:
        raise ContractError("TRUNCATED_ELF", "ELF binary too short for 64-bit header")
    if not data.startswith(_ELF_MAGIC):
        raise ContractError("INVALID_ELF", "Not an ELF binary")

    ei_class = data[4]
    ei_data = data[5]
    if ei_class != _ELFCLASS64:
        raise ContractError(
            "UNSUPPORTED_ELF",
            f"32-bit ELF binaries are strictly rejected (class={ei_class})",
            details={"ei_class": ei_class},
        )
    if ei_data != _ELFDATA2LSB:
        raise ContractError(
            "UNSUPPORTED_ELF",
            f"Big-endian ELF binaries are rejected (data={ei_data})",
            details={"ei_data": ei_data},
        )

    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if e_machine == _EM_X86_64:
        arch = "x86_64"
    elif e_machine == _EM_AARCH64:
        arch = "aarch64"
    else:
        raise ContractError(
            "UNSUPPORTED_ELF",
            f"Unsupported ELF e_machine: {e_machine}",
            details={"e_machine": e_machine},
        )

    return {
        "format": f"ELF 64-bit {arch}",
        "arch": arch,
        "e_machine": e_machine,
        "e_type": e_type,
    }


def inspect_macho_binary(data: bytes) -> dict[str, Any]:
    """Inspect and validate a 64-bit Mach-O binary header and load commands."""
    if len(data) < 32:
        raise ContractError("INVALID_MACHO", "Mach-O binary too short for 64-bit header")

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic in _MACHO_FAT_MAGICS:
        raise ContractError(
            "UNSUPPORTED_MACHO",
            "Universal/fat Mach-O binaries are strictly rejected",
            details={"magic": hex(magic)},
        )
    if magic in (_MACHO_MAGIC_32_LE, _MACHO_MAGIC_32_BE):
        raise ContractError(
            "UNSUPPORTED_MACHO",
            "32-bit Mach-O binaries are strictly rejected",
            details={"magic": hex(magic)},
        )
    if magic == _MACHO_MAGIC_64_BE:
        raise ContractError(
            "UNSUPPORTED_MACHO",
            "Big-endian Mach-O binaries are strictly rejected",
            details={"magic": hex(magic)},
        )
    if magic != _MACHO_MAGIC_64_LE:
        raise ContractError(
            "INVALID_MACHO",
            f"Unrecognized Mach-O magic: {hex(magic)}",
            details={"magic": hex(magic)},
        )

    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from("<iiIIIII", data, 4)
    if cputype == _CPU_TYPE_ARM64:
        arch = "arm64"
    elif cputype == _CPU_TYPE_X86_64:
        arch = "x86_64"
    else:
        raise ContractError(
            "UNSUPPORTED_MACHO",
            f"Unsupported Mach-O cputype: {hex(cputype)}",
            details={"cputype": cputype},
        )

    if 32 + sizeofcmds > len(data) or ncmds > sizeofcmds // 8:
        raise ContractError("INVALID_MACHO", "Mach-O load commands extend beyond file length")

    deployment_minimum: tuple[int, int] | None = None
    offset = 32
    for _ in range(ncmds):
        if offset + 8 > 32 + sizeofcmds:
            raise ContractError("INVALID_MACHO", "Truncated Mach-O load command")
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmdsize < 8 or cmdsize % 8 or offset + cmdsize > 32 + sizeofcmds:
            raise ContractError("INVALID_MACHO", "Invalid load command size")

        if cmd == _LC_BUILD_VERSION:
            if cmdsize < 24:
                raise ContractError("INVALID_MACHO", "Truncated LC_BUILD_VERSION command")
            platform, minos, sdk, ntools = struct.unpack_from("<IIII", data, offset + 8)
            if platform != _PLATFORM_MACOS:
                raise ContractError(
                    "INVALID_MACHO",
                    f"Expected macOS platform (1), got {platform}",
                    details={"platform": platform},
                )
            major = (minos >> 16) & 0xffff
            minor = (minos >> 8) & 0xff
            minimum = (major, minor + bool(minos & 0xff))
            deployment_minimum = max(deployment_minimum or (0, 0), minimum)
        elif cmd == _LC_VERSION_MIN_MACOSX:
            if cmdsize < 16:
                raise ContractError("INVALID_MACHO", "Truncated LC_VERSION_MIN_MACOSX command")
            version, sdk = struct.unpack_from("<II", data, offset + 8)
            major = (version >> 16) & 0xffff
            minor = (version >> 8) & 0xff
            minimum = (major, minor + bool(version & 0xff))
            deployment_minimum = max(deployment_minimum or (0, 0), minimum)

        offset += cmdsize
    if offset != 32 + sizeofcmds:
        raise ContractError("INVALID_MACHO", "Mach-O command inventory differs from declared size")

    return {
        "format": f"Mach-O 64-bit {arch}",
        "arch": arch,
        "cputype": cputype,
        "deployment_minimum": deployment_minimum,
    }


def extract_macho_deployment_minimum(data: bytes) -> tuple[int, int]:
    """Parse target Mach-O load commands deployment minimum with max((11, 0), version) floor.

    Fails closed if the deployment version command is missing, invalid, or truncated.
    """
    info = inspect_macho_binary(data)
    min_ver = info.get("deployment_minimum")
    if min_ver is None:
        raise ContractError(
            "INVALID_MACHO",
            "Missing deployment minimum load command (LC_BUILD_VERSION / LC_VERSION_MIN_MACOSX) in Mach-O binary",
        )
    major, minor = min_ver
    # macOS arm64 deployment minimum floor is at least 11.0
    return max((11, 0), (major, minor))


def inspect_binary_member(name: str, data: bytes) -> dict[str, Any]:
    """Inspect and validate binary member, rejecting PE, 32-bit, and unsupported formats."""
    if data.startswith(b"MZ"):
        raise ContractError(
            "UNSUPPORTED_BINARY",
            f"PE (Windows) binary format is strictly rejected: {name}",
            details={"path": name, "format": "PE"},
        )
    if data.startswith(_ELF_MAGIC):
        return inspect_elf_binary(data)
    if data.startswith((b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca")):
        return inspect_macho_binary(data)
    raise ContractError(
        "INVALID_BINARY",
        f"Unrecognized or unsupported binary format for {name}",
        details={"path": name},
    )


def evaluate_package_json_constraints(
    pkg_data_or_bytes: bytes | str | dict[str, Any],
    system: str,
) -> bool:
    """Qualify platform constraints (os/cpu) in package.json against target system or fail closed."""
    if isinstance(pkg_data_or_bytes, (bytes, str)):
        try:
            pkg = json.loads(pkg_data_or_bytes)
        except Exception as exc:
            raise ContractError("INVALID_METADATA", "Malformed package.json JSON content") from exc
    elif isinstance(pkg_data_or_bytes, dict):
        pkg = pkg_data_or_bytes
    else:
        raise ContractError("INVALID_METADATA", "Expected dict or bytes for package.json")

    if not isinstance(pkg, dict):
        raise ContractError("INVALID_METADATA", "Package metadata must be an object")
    platform_contract(system)
    target_os = "darwin" if "darwin" in system else "linux"
    target_cpu = "arm64" if ("aarch64" in system or "arm64" in system) else "x64"

    os_constraint = pkg.get("os")
    if os_constraint is not None:
        os_list = [os_constraint] if isinstance(os_constraint, str) else os_constraint
        if not isinstance(os_list, list) or any(not isinstance(o, str) or not o for o in os_list):
            raise ContractError("INVALID_METADATA", "Package OS constraints must be strings")
        negated = [o[1:] for o in os_list if o.startswith("!")]
        positive = [o for o in os_list if not o.startswith("!")]
        if target_os in negated:
            raise ContractError(
                "UNQUALIFIED_PLATFORM",
                f"Package OS constraint explicitly negates target OS {target_os}: {os_list}",
                details={"system": system, "target_os": target_os, "os_constraint": os_list},
            )
        if positive and target_os not in positive and "any" not in positive:
            raise ContractError(
                "UNQUALIFIED_PLATFORM",
                f"Target OS {target_os} not in permitted package OS list: {positive}",
                details={"system": system, "target_os": target_os, "os_constraint": os_list},
            )

    cpu_constraint = pkg.get("cpu")
    if cpu_constraint is not None:
        cpu_list = [cpu_constraint] if isinstance(cpu_constraint, str) else cpu_constraint
        if not isinstance(cpu_list, list) or any(not isinstance(c, str) or not c for c in cpu_list):
            raise ContractError("INVALID_METADATA", "Package CPU constraints must be strings")
        negated = [c[1:] for c in cpu_list if c.startswith("!")]
        positive = [c for c in cpu_list if not c.startswith("!")]
        if target_cpu in negated:
            raise ContractError(
                "UNQUALIFIED_PLATFORM",
                f"Package CPU constraint explicitly negates target CPU {target_cpu}: {cpu_list}",
                details={"system": system, "target_cpu": target_cpu, "cpu_constraint": cpu_list},
            )
        if positive and target_cpu not in positive and "any" not in positive:
            raise ContractError(
                "UNQUALIFIED_PLATFORM",
                f"Target CPU {target_cpu} not in permitted package CPU list: {positive}",
                details={"system": system, "target_cpu": target_cpu, "cpu_constraint": cpu_list},
            )

    return True


def validate_burst_native_prebuilds(
    payload_files: Mapping[str, bytes],
    payload_origins: Mapping[str, str],
    system: str,
    *,
    source_files: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    """Validate exactly closed native prebuild paths, origins, binary formats, and architecture admission.

    Enforces:
    - Target system must be one of the three supported wheel systems.
    - Exactly closed paths package/native/directory-snapshot/prebuilds/{darwin-arm64,darwin-x64,linux-arm64-gnu,linux-x64-gnu}/native-addon-posix-openat-v1.node
    - Release origin only (no npm-closure origin for native binaries).
    - Target present once, correct ELF64 LE e_machine / MachO64 arm64.
    - Reject fat/32bit/PE including prebuild path/suffix admission so magic detector omissions cannot allow others.
    - Foreign bytes and offline closure kept unchanged (no pruning).
    - Inspect package.json platform constraints explicitly or fail closed.
    """
    if system not in SUPPORTED_WHEEL_SYSTEMS:
        raise ContractError(
            "INVALID_ARCHITECTURE",
            f"Unsupported wheel system: {system}",
            details={"system": system},
        )

    contract = platform_contract(system)
    target_prebuild_key = BURST_SYSTEM_TO_PREBUILD_KEY[system]
    target_prebuild_path = BURST_CLOSED_PREBUILDS[target_prebuild_key]

    # 1. Target prebuild presence
    if target_prebuild_path not in payload_files:
        raise ContractError(
            "MISSING_ASSET",
            f"Target native addon prebuild missing from release payload: {target_prebuild_path}",
            details={
                "system": system,
                "target_key": target_prebuild_key,
                "target_path": target_prebuild_path,
            },
        )

    # 2. Strict scan across entire payload inventory
    target_info: dict[str, Any] | None = None
    inspected_prebuilds: dict[str, dict[str, Any]] = {}

    for name, data in payload_files.items():
        origin = payload_origins.get(name, "unknown")

        # Check for package.json platform constraints
        if name.endswith("/package.json") or name == "package.json":
            evaluate_package_json_constraints(data, system)

        # Check prebuild directory boundary
        is_in_prebuild_dir = name.startswith(f"{BURST_PREBUILD_SUBDIR}/")
        is_node_addon = name.endswith(".node")
        has_binary_magic = is_native_payload(name, data)
        # Released manifests in these folders remain authenticated inert metadata.
        metadata_paths = {p.rsplit("/", 1)[0] + "/manifest.json" for p in BURST_CLOSED_PREBUILD_PATHS}
        if is_in_prebuild_dir and name in metadata_paths and not has_binary_magic:
            if origin != "release-payload":
                raise ContractError("UNQUALIFIED_PLATFORM", "Prebuild metadata must be released payload")
            try:
                if not isinstance(json.loads(data), dict):
                    raise ValueError
            except (TypeError, ValueError):
                raise ContractError("INVALID_METADATA", "Prebuild manifest must be an authenticated JSON object") from None
            continue

        # Check unauthorized native files outside or inside prebuilds
        if is_node_addon or has_binary_magic or is_in_prebuild_dir:
            # Must be one of the exactly closed prebuild paths
            if name not in BURST_CLOSED_PREBUILD_PATHS:
                raise ContractError(
                    "UNQUALIFIED_PLATFORM",
                    f"Unauthorized native member or prebuild path: {name}",
                    details={
                        "product": BURST_PRODUCT_ID,
                        "substage": "burst-native-scan",
                        "archive_path": name,
                        "origin": origin,
                        "reason": "unauthorized-native-or-prebuild-path",
                    },
                )

            # Must originate from release-payload exclusively
            if origin != "release-payload":
                raise ContractError(
                    "UNQUALIFIED_PLATFORM",
                    f"Native prebuild {name} has unapproved origin {origin!r}; release origin required",
                    details={
                        "product": BURST_PRODUCT_ID,
                        "substage": "burst-native-scan",
                        "archive_path": name,
                        "origin": origin,
                        "reason": "non-release-payload-origin",
                    },
                )

            # Inspect binary format
            info = inspect_binary_member(name, data)
            key = [k for k, p in BURST_CLOSED_PREBUILDS.items() if p == name][0]
            inspected_prebuilds[key] = info

            # Expected architecture per closed prebuild folder
            if key == "darwin-arm64":
                if info["format"] != "Mach-O 64-bit arm64" or info["arch"] != "arm64":
                    raise ContractError(
                        "INVALID_ARCHITECTURE",
                        f"darwin-arm64 prebuild must be Mach-O 64-bit arm64, got {info['format']}",
                        details={"path": name, "info": info},
                    )
                # Verify deployment minimum parseable
                extract_macho_deployment_minimum(data)
            elif key == "darwin-x64":
                if info["format"] != "Mach-O 64-bit x86_64" or info["arch"] != "x86_64":
                    raise ContractError(
                        "INVALID_ARCHITECTURE",
                        f"darwin-x64 prebuild must be Mach-O 64-bit x86_64, got {info['format']}",
                        details={"path": name, "info": info},
                    )
            elif key == "linux-arm64-gnu":
                if info["format"] != "ELF 64-bit aarch64" or info["arch"] != "aarch64":
                    raise ContractError(
                        "INVALID_ARCHITECTURE",
                        f"linux-arm64-gnu prebuild must be ELF 64-bit aarch64, got {info['format']}",
                        details={"path": name, "info": info},
                    )
            elif key == "linux-x64-gnu":
                if info["format"] != "ELF 64-bit x86_64" or info["arch"] != "x86_64":
                    raise ContractError(
                        "INVALID_ARCHITECTURE",
                        f"linux-x64-gnu prebuild must be ELF 64-bit x86_64, got {info['format']}",
                        details={"path": name, "info": info},
                    )

            if name == target_prebuild_path:
                target_info = info

    # Evaluate tagged source package.json if supplied
    if source_files and "package.json" in source_files:
        evaluate_package_json_constraints(source_files["package.json"], system)

    if target_info is None:
        raise ContractError(
            "MISSING_ASSET",
            f"Target prebuild was not inspected: {target_prebuild_path}",
        )

    # Validate target architecture matches expected platform arch
    expected_arch = contract.expected_binary_arch
    if target_info["arch"] != expected_arch:
        raise ContractError(
            "INVALID_ARCHITECTURE",
            f"Target prebuild arch {target_info['arch']} does not match expected {expected_arch} for {system}",
            details={
                "system": system,
                "expected_arch": expected_arch,
                "actual_arch": target_info["arch"],
                "target_path": target_prebuild_path,
            },
        )

    return {
        "target_key": target_prebuild_key,
        "target_path": target_prebuild_path,
        "target_info": target_info,
        "inspected_prebuilds": inspected_prebuilds,
    }


def resolve_burst_platform_wheel_tag(
    system: str,
    target_macho_bytes: bytes | None = None,
    requested_tag: str | None = None,
) -> tuple[str, str]:
    """Resolve and validate truthful platform and wheel tags for Stellar Burst.

    Enforces:
    - Tags ONLY linux_x86_64 / linux_aarch64 / macOS arm64 appropriate floor.
    - NO manylinux / musllinux / x64 Darwin.
    - Target Mach-O deployment minimum floor enforced for Darwin arm64.
    """
    if system not in SUPPORTED_WHEEL_SYSTEMS:
        raise ContractError("INVALID_ARCHITECTURE", f"Unsupported wheel system: {system}")

    if requested_tag == "any":
        raise ContractError("UNSUPPORTED_PLATFORM", "Native Burst platform wheel cannot use fake universal 'any' tag")

    if requested_tag and ("manylinux" in requested_tag or "musllinux" in requested_tag):
        raise ContractError(
            "UNSUPPORTED_PLATFORM",
            f"Linux platform tags must NOT claim manylinux or musllinux compliance: {requested_tag!r}",
            details={"requested_tag": requested_tag, "system": system},
        )

    if system == "aarch64-darwin":
        if target_macho_bytes is None:
            raise ContractError("INVALID_MACHO", "Target Mach-O binary bytes required to resolve Darwin deployment floor")

        floor_major, floor_minor = extract_macho_deployment_minimum(target_macho_bytes)
        expected_platform_tag = f"macosx_{floor_major}_{floor_minor}_arm64"

        if requested_tag:
            m = re.fullmatch(r"^macosx_(\d+)_(\d+)_arm64$", requested_tag)
            if not m:
                raise ContractError(
                    "UNSUPPORTED_PLATFORM",
                    f"Darwin platform tag must match macosx_[major]_[minor]_arm64 (no x86_64), got {requested_tag!r}",
                    details={"requested_tag": requested_tag},
                )
            req_major = int(m.group(1))
            req_minor = int(m.group(2))
            if req_major < 11:
                raise ContractError(
                    "UNSUPPORTED_PLATFORM",
                    f"Darwin arm64 requires deployment floor >= 11.0, got {requested_tag!r}",
                )
            if (req_major, req_minor) < (floor_major, floor_minor):
                raise ContractError(
                    "UNSUPPORTED_PLATFORM",
                    f"Requested tag {requested_tag!r} is lower than Mach-O deployment minimum ({floor_major}.{floor_minor})",
                )
            resolved_platform_tag = requested_tag
        else:
            resolved_platform_tag = expected_platform_tag

        return resolved_platform_tag, f"py3-none-{resolved_platform_tag}"

    elif system == "x86_64-linux":
        if requested_tag and requested_tag != "linux_x86_64":
            raise ContractError(
                "UNSUPPORTED_PLATFORM",
                f"x86_64 Linux requires tag 'linux_x86_64', got {requested_tag!r}",
            )
        return "linux_x86_64", "py3-none-linux_x86_64"

    elif system == "aarch64-linux":
        if requested_tag and requested_tag != "linux_aarch64":
            raise ContractError(
                "UNSUPPORTED_PLATFORM",
                f"aarch64 Linux requires tag 'linux_aarch64', got {requested_tag!r}",
            )
        return "linux_aarch64", "py3-none-linux_aarch64"

    raise ContractError("INVALID_ARCHITECTURE", f"Unsupported system: {system}")


def make_burst_native_provenance(
    system: str,
    target_path: str,
    target_bytes: bytes,
    target_info: dict[str, Any],
    payload_files: Mapping[str, bytes] | None = None,
) -> dict[str, Any]:
    """Generate canonical provenance record fields for Stellar Burst platform wheels."""
    target_hash = digest(target_bytes)
    is_darwin = system == "aarch64-darwin"

    return {
        "platform_specific": True,
        "target_system": system,
        "target_native_addon": {
            "identity": target_path,
            "path": target_path,
            "hash": target_hash,
            "sha256": target_hash,
            "size": len(target_bytes),
            "format": target_info["format"],
            "arch": target_info["arch"],
            "architecture": target_info["arch"],
            **({"macos_minimum": list(target_info["deployment_minimum"])} if is_darwin else {}),
        },
        "foreign_prebuilds": [{"path": path, "sha256": digest(payload_files[path]),
                               "size": len(payload_files[path]),
                               "architecture": inspect_binary_member(path, payload_files[path])["arch"],
                               "disposition": "retained-inert"}
                              for path in sorted(BURST_CLOSED_PREBUILD_PATHS)
                              if payload_files and path in payload_files and path != target_path],
        "downstream_transform": "none",
        "native_loader": ({"path": "package/dist/directory-snapshot-native.js",
                           "sha256": digest(payload_files["package/dist/directory-snapshot-native.js"])}
                          if payload_files and "package/dist/directory-snapshot-native.js" in payload_files else None),
        "production_promotion": (
            "candidate-only-attended-policy-required" if is_darwin
            else "blocked-linux-compatibility-unproven"
        ),
        "linux_compatibility": {
            "status": "not-proved",
            "compatible": False,
            "manylinux_proven": False,
            "musllinux_proven": False,
            "glibc_version_needs": "not-proved",
        },
        "candidate_only": True,
        "promotability": "candidate" if is_darwin else "policy-pending",
        "manylinux_proven": False,
        "musllinux_proven": False,
        "linux_compatible": False,
        "linux_compatibility_proven": False,
        "linux_compatibility_status": "not-proved",
    }


# Authentic released loader module and lazy invocation route in retained captures
RELEASED_LOADER_INFO: Mapping[str, Any] = types.MappingProxyType({
    "loader_module": "package/dist/directory-snapshot-native.js",
    "loader_source": "src/directory-snapshot-native.ts",
    "loader_export": "loadDirectorySnapshotNative()",
    "loader_sha256": "23a3bf942fa1f92fbf686b4cedc0ec2a9f6653ded6fd2df7ef9d3c58d6591e69",
    "loader_size": 3639,
    "addon_name": BURST_BACKEND_NAME,
    "addon_abi": 1,
    "addon_relpath": f"native/directory-snapshot/prebuilds/${{artifact}}/{BURST_BACKEND_NAME}.node",
    "loader_mechanism": "Node.js createRequire(import.meta.url)(artifactPath) with addon shape check and self-test verification",
    "dlopen_behavior": "exactly-once-memoized",
    "exported_symbols": [
        "DIRECTORY_SNAPSHOT_BACKEND",
        "DIRECTORY_SNAPSHOT_BACKEND_ABI",
        "currentDirectorySnapshotArtifact",
        "loadDirectorySnapshotNative",
    ],
    "result_contract": {
        "success": {"ok": True, "artifact": "str", "addon": "object"},
        "failure": {"ok": False, "artifact": "str", "reason": "str"},
        "failure_reasons": [
            "unsupported-platform",
            "artifact-missing-or-corrupt",
            "backend-mismatch",
            "self-test-failed",
        ],
    },
    "prebuild_sha256s": {
        "darwin-arm64": "2f842ce43f62c76b04884a92980037067c8e55dfd183c86e788f1c3ac8a533c8",
        "darwin-x64": "41eb0b3091173132012565560d62b31f7320764c6fd6e780994fcef8803704c6",
        "linux-arm64-gnu": "67fb6b85f339a7c2f43ababa20434b26a3ea9bb65b17e70257a03c07810beb79",
        "linux-x64-gnu": "a2999fc9ac1b1f0a31600595f7069e10aadb032f01059b4d7e64ed80cd8a38a8",
    },
    "lazy_invocation_routes": [
        {
            "module": "package/dist/directory-snapshot.js",
            "source": "src/directory-snapshot.ts",
            "functions": [
                "getDirectorySnapshotCapability(root)",
                "qualifyDirectorySnapshotPlatform(root)",
                "createDirectorySnapshot(root, map, collectionIds, options)",
            ],
            "trigger_entrypoints": [
                "package/dist/cli.js (tfsb)",
                "package/dist/service-protocol/server-cli.js (tfsb-studio-service)",
            ],
            "invocation_behavior": "Lazy: the native addon is only required when directory snapshot operations are executed; startup and non-snapshot commands execute pure JS.",
        },
    ],
})
