"""Tests for Stellar Burst native platform wheel build boundary and adverse conditions."""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

from rs9.burst_native import (
    BURST_CLOSED_PREBUILDS,
    BURST_PRODUCT_ID,
    RELEASED_LOADER_INFO,
    extract_macho_deployment_minimum,
    inspect_elf_binary,
    inspect_macho_binary,
    resolve_burst_platform_wheel_tag,
    validate_burst_native_prebuilds,
)
from rs9.errors import ContractError
from rs9.release_core import ReleaseCapture, authenticate_release, digest
from rs9.scratch import canonical
from rs9.verify_wheel import verify_double_build, verify_wheel_record_bidirectional
from rs9.wheel import inspect_wheel
from rs9.wheel_capture import build_capture_wheel as _build_capture_wheel


def build_capture_wheel(*args, **kwargs):
    return _build_capture_wheel(*args, fixture_only=True, **kwargs)


def make_synthetic_macho(
    arch: str = "arm64",
    major: int = 13,
    minor: int = 0,
    patch: int = 0,
    *,
    use_min_macosx: bool = False,
    omit_load_command: bool = False,
    truncate_load_command: bool = False,
    cputype_override: int | None = None,
    magic_override: int | None = None,
) -> bytes:
    """Build synthetic 64-bit Mach-O binary with valid LC_BUILD_VERSION or LC_VERSION_MIN_MACOSX."""
    magic = magic_override if magic_override is not None else 0xfeedfacf
    cputype = cputype_override if cputype_override is not None else (0x0100000c if arch == "arm64" else 0x01000007)
    cpusubtype = 0
    filetype = 8  # MH_BUNDLE
    flags = 0
    reserved = 0

    if omit_load_command:
        ncmds = 0
        sizeofcmds = 0
        header = struct.pack("<IIIIIIII", magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved)
        return header + b"\x00" * 32

    if use_min_macosx:
        cmd = 0x24  # LC_VERSION_MIN_MACOSX
        cmdsize = 16
        version = (major << 16) | (minor << 8) | patch
        sdk = (major << 16) | (minor << 8) | patch
        cmd_bytes = struct.pack("<IIII", cmd, cmdsize, version, sdk)
    else:
        cmd = 0x32  # LC_BUILD_VERSION
        cmdsize = 24
        platform = 1  # PLATFORM_MACOS
        minos = (major << 16) | (minor << 8) | patch
        sdk = (major << 16) | (minor << 8) | patch
        ntools = 0
        cmd_bytes = struct.pack("<IIIIII", cmd, cmdsize, platform, minos, sdk, ntools)

    if truncate_load_command:
        cmd_bytes = cmd_bytes[:6]

    ncmds = 1
    sizeofcmds = len(cmd_bytes)
    header = struct.pack("<IIIIIIII", magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved)
    return header + cmd_bytes + b"\x90" * 32


def make_synthetic_elf(
    arch: str = "x86_64",
    *,
    ei_class: int = 2,
    ei_data: int = 1,
    e_machine_override: int | None = None,
    truncate: bool = False,
) -> bytes:
    """Build synthetic ELF64 binary with specific e_machine."""
    magic = b"\x7fELF"
    ident = magic + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    e_type = 3  # ET_DYN (shared object)
    if e_machine_override is not None:
        e_machine = e_machine_override
    else:
        e_machine = 62 if arch == "x86_64" else 183
    e_version = 1
    e_entry = 0x1000
    e_phoff = 64
    e_shoff = 0
    e_flags = 0
    e_ehsize = 64
    e_phentsize = 56
    e_phnum = 1
    e_shentsize = 64
    e_shnum = 0
    e_shstrndx = 0

    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    )
    # 1 load program header
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 128, 128, 0x1000)
    body = header + phdr + b"\x00" * 32
    return body[:20] if truncate else body


def make_synthetic_archive(entries: list[tuple[str, bytes, int, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, data, mode, kind in entries:
            ti = tarfile.TarInfo(path)
            ti.mode = mode
            ti.type = kind
            ti.size = len(data) if kind == tarfile.REGTYPE else 0
            tf.addfile(ti, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return buf.getvalue()


def create_burst_test_capture(
    directory: Path,
    *,
    extra_sources: dict[str, bytes] | None = None,
    darwin_arm64_bytes: bytes | None = None,
    darwin_x64_bytes: bytes | None = None,
    linux_arm64_bytes: bytes | None = None,
    linux_x64_bytes: bytes | None = None,
    omit_prebuild_key: str | None = None,
    extra_prebuilds: list[tuple[str, bytes]] | None = None,
    package_json_extra: dict | None = None,
) -> tuple[dict, ReleaseCapture, dict[str, Path]]:
    """Build a complete authentic-shape synthetic Stellar Burst capture with all 4 prebuilds and lock."""
    pkg_dict = {
        "name": "theme-forge-stellar-burst",
        "version": "0.6.1",
        "license": "AGPL-3.0-or-later",
        "dependencies": {"burst-runtime-dep": "1.0.0"},
    }
    if package_json_extra:
        pkg_dict.update(package_json_extra)

    dep_tar = make_synthetic_archive([
        ("package", b"", 0o755, tarfile.DIRTYPE),
        ("package/package.json", canonical({"name": "burst-runtime-dep", "version": "1.0.0", "license": "MIT"}), 0o644, tarfile.REGTYPE),
        ("package/index.js", b"module.exports = 'burst-dep';\n", 0o644, tarfile.REGTYPE),
        ("package/LICENSE", b"MIT License\n", 0o644, tarfile.REGTYPE),
    ])
    dep_archive_path = directory / "burst-runtime-dep-1.0.0.tgz"
    dep_archive_path.parent.mkdir(parents=True, exist_ok=True)
    dep_archive_path.write_bytes(dep_tar)

    dep_integrity = "sha512-" + base64.b64encode(hashlib.sha512(dep_tar).digest()).decode("ascii")
    dep_rel = "node_modules/burst-runtime-dep"

    lock_dict = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"burst-runtime-dep": "1.0.0"}},
            dep_rel: {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/burst-runtime-dep/-/burst-runtime-dep-1.0.0.tgz",
                "integrity": dep_integrity,
            },
        },
    }

    sources = {
        "LICENSE": b"Synthetic AGPL-3.0-or-later license text.\n",
        "NOTICE": b"Synthetic notice.\n",
        "package.json": canonical(pkg_dict),
        "package-lock.json": canonical(lock_dict),
        **(extra_sources or {}),
    }

    (directory / "source").mkdir(parents=True, exist_ok=True)
    tree = []
    for p, b in sources.items():
        (directory / "source" / p).write_bytes(b)
        blob = hashlib.sha1(b"blob " + str(len(b)).encode("ascii") + b"\0" + b).hexdigest()
        tree.append({"path": p, "type": "blob", "mode": "100644", "sha": blob})

    # Default valid prebuild binaries
    prebuild_binaries = {
        "darwin-arm64": darwin_arm64_bytes or make_synthetic_macho("arm64", 13, 0),
        "darwin-x64": darwin_x64_bytes or make_synthetic_macho("x86_64", 15, 0),
        "linux-arm64-gnu": linux_arm64_bytes or make_synthetic_elf("aarch64"),
        "linux-x64-gnu": linux_x64_bytes or make_synthetic_elf("x86_64"),
    }

    tar_entries = [
        ("package", b"", 0o755, tarfile.DIRTYPE),
        ("package/package.json", sources["package.json"], 0o644, tarfile.REGTYPE),
        ("package/dist", b"", 0o755, tarfile.DIRTYPE),
        ("package/dist/cli.js", b"console.log('burst cli 0.6.1');\n", 0o755, tarfile.REGTYPE),
        ("package/dist/service-protocol", b"", 0o755, tarfile.DIRTYPE),
        ("package/dist/service-protocol/server-cli.js", b"console.log('burst server 0.6.1');\n", 0o755, tarfile.REGTYPE),
        ("package/LICENSE", sources["LICENSE"], 0o644, tarfile.REGTYPE),
        ("package/NOTICE", sources["NOTICE"], 0o644, tarfile.REGTYPE),
    ]

    for key, path in BURST_CLOSED_PREBUILDS.items():
        if key == omit_prebuild_key:
            continue
        tar_entries.append((path, prebuild_binaries[key], 0o755, tarfile.REGTYPE))

    if extra_prebuilds:
        for ep_path, ep_data in extra_prebuilds:
            tar_entries.append((ep_path, ep_data, 0o755, tarfile.REGTYPE))

    pkg_tgz = make_synthetic_archive(tar_entries)
    archive_name = "knowledge-forge-ai-theme-forge-stellar-burst-0.6.1.tgz"

    assets_raw = {
        archive_name: pkg_tgz,
        "NOTICE": sources["NOTICE"],
        "PROVENANCE.json": canonical({"release": {"repository": "Knowledge-Forge-AI/theme-forge-stellar-burst"}}),
    }
    sums = "".join(f"{digest(b)}  {n}\n" for n, b in sorted(assets_raw.items())).encode()
    assets_raw["SHA256SUMS"] = sums

    (directory / "assets").mkdir(parents=True, exist_ok=True)
    for n, b in assets_raw.items():
        (directory / "assets" / n).write_bytes(b)

    gh_assets = [
        {"id": i + 1, "name": n, "size": len(b), "digest": "sha256:" + digest(b), "state": "uploaded"}
        for i, (n, b) in enumerate(assets_raw.items())
    ]
    meta = {
        "repository": {"id": 102, "full_name": "Knowledge-Forge-AI/theme-forge-stellar-burst"},
        "release": {"id": 202, "tag_name": "v0.6.1", "target_commitish": "a" * 40, "draft": False, "prerelease": False, "assets": gh_assets},
        "ref": {"ref": "refs/tags/v0.6.1", "object": {"type": "commit", "sha": "a" * 40}},
        "tags": [],
        "commit": {"sha": "a" * 40, "tree": {"sha": "b" * 40}},
        "tree": {"sha": "b" * 40, "truncated": False, "tree": tree},
    }
    (directory / "api").mkdir(parents=True, exist_ok=True)
    for n, v in meta.items():
        (directory / "api" / (n + ".json")).write_bytes(canonical(v))

    selection = {
        "schema": "rs9.release-selection.v1alpha1",
        "repository": "Knowledge-Forge-AI/theme-forge-stellar-burst",
        "tag": "v0.6.1",
        "prerelease": "reject",
        "checksums": "SHA256SUMS",
        "payload_assets": [{
            "id": "package",
            "name": archive_name,
            "format": "tar.gz",
            "commands": {
                "tfsb": "package/dist/cli.js",
                "tfsb-studio-service": "package/dist/service-protocol/server-cli.js",
            },
            "launchers": {},
            "platforms": ["any"],
        }],
        "evidence_assets": [
            {"name": "NOTICE", "role": "notice"},
            {"name": "PROVENANCE.json", "role": "provenance"},
        ],
        "source_paths": sorted(sources.keys()),
    }
    capture = authenticate_release(selection, directory)
    return selection, capture, {dep_rel: dep_archive_path}


class BurstPlatformWheelTests(unittest.TestCase):
    def test_release_prebuild_metadata_is_retained_but_cannot_hide_native_bytes(self):
        """[SYNTHETIC] Verify prebuild metadata retention with synthetic Mach-O/ELF binaries."""
        files = {BURST_CLOSED_PREBUILDS["darwin-arm64"]: make_synthetic_macho(),
                 BURST_CLOSED_PREBUILDS["darwin-x64"]: make_synthetic_macho("x86_64"),
                 BURST_CLOSED_PREBUILDS["linux-arm64-gnu"]: make_synthetic_elf("aarch64"),
                 BURST_CLOSED_PREBUILDS["linux-x64-gnu"]: make_synthetic_elf()}
        metadata = BURST_CLOSED_PREBUILDS["linux-x64-gnu"].rsplit("/", 1)[0] + "/manifest.json"
        files[metadata] = b'{"backend":"native-addon-posix-openat-v1"}'
        origins = {p: "release-payload" for p in files}
        result = validate_burst_native_prebuilds(files, origins, "x86_64-linux")
        self.assertEqual(len(result["inspected_prebuilds"]), 4)
        self.assertEqual(files[metadata], b'{"backend":"native-addon-posix-openat-v1"}')
        for data in (b"MZ" + b"x" * 100, b"not-json", b"[]"):
            with self.assertRaises(ContractError):
                validate_burst_native_prebuilds({**files, metadata: data}, origins, "x86_64-linux")

    def test_malformed_macho_command_bounds_fail_closed(self):
        """[SYNTHETIC] Malformed synthetic Mach-O command bounds fail closed."""
        data = bytearray(make_synthetic_macho())
        for offset, value in ((16, 10000), (20, 0), (36, 1000)):
            broken = bytearray(data)
            struct.pack_into("<I", broken, offset, value)
            with self.assertRaises(ContractError): inspect_macho_binary(bytes(broken))

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def test_positive_all_three_synthetic_platform_wheels_deterministic(self) -> None:
        """[SYNTHETIC] Verify deterministic builds for all three supported systems with truthful tags and RECORD parity."""
        systems = [
            ("aarch64-darwin", "macosx_13_0_arm64", "theme_forge_stellar_burst-0.6.1-py3-none-macosx_13_0_arm64.whl"),
            ("x86_64-linux", "linux_x86_64", "theme_forge_stellar_burst-0.6.1-py3-none-linux_x86_64.whl"),
            ("aarch64-linux", "linux_aarch64", "theme_forge_stellar_burst-0.6.1-py3-none-linux_aarch64.whl"),
        ]

        for system, expected_platform_tag, expected_filename in systems:
            with self.subTest(system=system):
                evidence_dir = self.root / f"evidence_{system}"
                _, capture, dep_archives = create_burst_test_capture(evidence_dir)

                res_a, res_b = verify_double_build(
                    build_capture_wheel,
                    BURST_PRODUCT_ID,
                    "0.6.1",
                    capture,
                    system=system,
                    dependency_archives=dep_archives,
                    integrate_closure=True,
                    output_dir_a=self.root / f"build_a_{system}",
                    output_dir_b=self.root / f"build_b_{system}",
                )

                # Determinism verification
                self.assertEqual(res_a.wheel_bytes, res_b.wheel_bytes)
                self.assertEqual(res_a.sha256, res_b.sha256)
                self.assertEqual(res_a.filename, expected_filename)
                self.assertEqual(res_a.tag, f"py3-none-{expected_platform_tag}")

                # Strict bidirectional RECORD verification
                inv = verify_wheel_record_bidirectional(res_a.wheel_path)
                self.assertTrue(inv["record_valid"])

                # Verify payload closure: all four prebuild paths remain present and unpruned
                for path in BURST_CLOSED_PREBUILDS.values():
                    expected_arc = f"theme_forge_stellar_burst/payload/{path}"
                    self.assertIn(expected_arc, inv["entries"])

                # Verify dependency closure is intact
                self.assertIn(
                    "theme_forge_stellar_burst/payload/package/node_modules/burst-runtime-dep/index.js",
                    inv["entries"],
                )

                # Verify provenance and manifest contract
                rec = res_a.record
                self.assertTrue(rec["platform_specific"])
                self.assertEqual(rec["target_system"], system)
                self.assertEqual(len(rec["foreign_prebuilds"]), 3)
                self.assertTrue(all(r["disposition"] == "retained-inert" and len(r["sha256"]) == 64 for r in rec["foreign_prebuilds"]))
                self.assertEqual(rec["downstream_transform"], "none")
                self.assertFalse(rec["can_publish"])
                self.assertTrue(rec["candidate_only"])
                self.assertFalse(rec["manylinux_proven"])
                self.assertFalse(rec["linux_compatible"])

                # System-specific promotion and format checks
                addon_info = rec["target_native_addon"]
                self.assertIn("identity", addon_info)
                self.assertIn("hash", addon_info)
                self.assertIn("format", addon_info)
                self.assertIn("arch", addon_info)

                if system == "aarch64-darwin":
                    self.assertEqual(addon_info["format"], "Mach-O 64-bit arm64")
                    self.assertEqual(addon_info["arch"], "arm64")
                    self.assertEqual(rec["production_promotion"], "candidate-only-attended-policy-required")
                    self.assertEqual(rec["promotability"], "candidate")
                else:
                    self.assertEqual(rec["production_promotion"], "blocked-linux-compatibility-unproven")
                    self.assertEqual(rec["promotability"], "policy-pending")
                    self.assertIn("ELF 64-bit", addon_info["format"])
                    self.assertFalse(rec["linux_compatibility"]["compatible"])
                    self.assertFalse(rec["linux_compatibility"]["manylinux_proven"])
                    self.assertEqual(rec["linux_compatibility"]["status"], "not-proved")

    def test_target_missing_fails_closed(self) -> None:
        """[SYNTHETIC] Target prebuild missing from release payload raises MISSING_ASSET."""
        for system, missing_key in [("aarch64-darwin", "darwin-arm64"), ("x86_64-linux", "linux-x64-gnu"), ("aarch64-linux", "linux-arm64-gnu")]:
            with self.subTest(system=system):
                evidence_dir = self.root / f"evidence_missing_{system}"
                _, capture, dep_archives = create_burst_test_capture(evidence_dir, omit_prebuild_key=missing_key)

                with self.assertRaises(ContractError) as ctx:
                    build_capture_wheel(
                        BURST_PRODUCT_ID,
                        "0.6.1",
                        capture,
                        system=system,
                        dependency_archives=dep_archives,
                        integrate_closure=True,
                        output_dir=self.root / f"out_missing_{system}",
                    )
                self.assertEqual(ctx.exception.code, "MISSING_ASSET")

    def test_target_wrong_architecture_fails_closed(self) -> None:
        """[SYNTHETIC] Target prebuild having wrong machine / binary format fails closed with INVALID_ARCHITECTURE."""
        # 1. Linux x86_64 target with an aarch64 binary
        evidence_dir1 = self.root / "evidence_wrong_x86"
        _, capture1, dep_archives1 = create_burst_test_capture(
            evidence_dir1,
            linux_x64_bytes=make_synthetic_elf("aarch64"),
        )
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture1,
                system="x86_64-linux",
                dependency_archives=dep_archives1,
                integrate_closure=True,
                output_dir=self.root / "out_wrong_x86",
            )
        self.assertEqual(ctx.exception.code, "INVALID_ARCHITECTURE")

        # 2. Darwin arm64 target with an x86_64 Mach-O
        evidence_dir2 = self.root / "evidence_wrong_darwin"
        _, capture2, dep_archives2 = create_burst_test_capture(
            evidence_dir2,
            darwin_arm64_bytes=make_synthetic_macho("x86_64", 13, 0),
        )
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture2,
                system="aarch64-darwin",
                dependency_archives=dep_archives2,
                integrate_closure=True,
                output_dir=self.root / "out_wrong_darwin",
            )
        self.assertEqual(ctx.exception.code, "INVALID_ARCHITECTURE")

        # 3. Linux aarch64 target with an x86_64 binary
        evidence_dir3 = self.root / "evidence_wrong_arm64"
        _, capture3, dep_archives3 = create_burst_test_capture(
            evidence_dir3,
            linux_arm64_bytes=make_synthetic_elf("x86_64"),
        )
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture3,
                system="aarch64-linux",
                dependency_archives=dep_archives3,
                integrate_closure=True,
                output_dir=self.root / "out_wrong_arm64",
            )
        self.assertEqual(ctx.exception.code, "INVALID_ARCHITECTURE")

    def test_foreign_prebuild_fat_32bit_pe_negatives_fail_closed(self) -> None:
        """[SYNTHETIC] Any foreign prebuild having PE, 32-bit ELF, or fat Mach-O format fails closed."""
        # 1. Foreign prebuild has PE header
        evidence_pe = self.root / "evidence_pe"
        _, capture_pe, dep_pe = create_burst_test_capture(
            evidence_pe,
            darwin_x64_bytes=b"MZ\x90\x00" + b"\x00" * 60,
        )
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture_pe,
                system="x86_64-linux",
                dependency_archives=dep_pe,
                integrate_closure=True,
                output_dir=self.root / "out_pe",
            )
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_BINARY")

        # 2. Foreign prebuild is 32-bit ELF (ei_class=1)
        evidence_32bit = self.root / "evidence_32bit"
        _, capture_32, dep_32 = create_burst_test_capture(
            evidence_32bit,
            linux_arm64_bytes=make_synthetic_elf("aarch64", ei_class=1),
        )
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture_32,
                system="x86_64-linux",
                dependency_archives=dep_32,
                integrate_closure=True,
                output_dir=self.root / "out_32bit",
            )
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_ELF")

        # 3. Foreign prebuild is Universal / Fat Mach-O (0xcafebabe)
        evidence_fat = self.root / "evidence_fat"
        fat_magic_bytes = struct.pack(">I", 0xcafebabe) + b"\x00" * 60
        _, capture_fat, dep_fat = create_burst_test_capture(
            evidence_fat,
            darwin_x64_bytes=fat_magic_bytes,
        )
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture_fat,
                system="x86_64-linux",
                dependency_archives=dep_fat,
                integrate_closure=True,
                output_dir=self.root / "out_fat",
            )
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_MACHO")

    def test_unauthorized_prebuild_path_and_suffix_negatives(self) -> None:
        """[SYNTHETIC] Only exactly closed prebuild paths and release origin are admitted; all others fail closed."""
        # 1. Unexpected extra prebuild folder (e.g. win32-x64)
        evidence_unauth = self.root / "evidence_unauth"
        _, capture_unauth, dep_unauth = create_burst_test_capture(
            evidence_unauth,
            extra_prebuilds=[(
                "package/native/directory-snapshot/prebuilds/win32-x64/native-addon-posix-openat-v1.node",
                make_synthetic_elf("x86_64"),
            )],
        )
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture_unauth,
                system="x86_64-linux",
                dependency_archives=dep_unauth,
                integrate_closure=True,
                output_dir=self.root / "out_unauth",
            )
        self.assertEqual(ctx.exception.code, "UNQUALIFIED_PLATFORM")

        # 2. Unauthorized suffix (e.g. extra.node) in valid prebuild folder
        evidence_extra = self.root / "evidence_extra"
        _, capture_extra, dep_extra = create_burst_test_capture(
            evidence_extra,
            extra_prebuilds=[(
                "package/native/directory-snapshot/prebuilds/linux-x64-gnu/extra.node",
                make_synthetic_elf("x86_64"),
            )],
        )
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture_extra,
                system="x86_64-linux",
                dependency_archives=dep_extra,
                integrate_closure=True,
                output_dir=self.root / "out_extra",
            )
        self.assertEqual(ctx.exception.code, "UNQUALIFIED_PLATFORM")

    def test_macho_deployment_minimum_parsing_and_tag_floor(self) -> None:
        """[SYNTHETIC] Target Mach-O deployment minimum load commands are parsed with max((11, 0), version) floor."""
        # 1. Mach-O with minos 10.15 (should get floored to 11.0)
        evidence_floor = self.root / "evidence_floor_11"
        _, capture_floor, dep_floor = create_burst_test_capture(
            evidence_floor,
            darwin_arm64_bytes=make_synthetic_macho("arm64", major=10, minor=15),
        )
        res = build_capture_wheel(
            BURST_PRODUCT_ID,
            "0.6.1",
            capture_floor,
            system="aarch64-darwin",
            dependency_archives=dep_floor,
            integrate_closure=True,
            output_dir=self.root / "out_floor_11",
        )
        self.assertEqual(res.tag, "py3-none-macosx_11_0_arm64")

        # 2. Missing deployment load command fails closed
        evidence_no_cmd = self.root / "evidence_no_cmd"
        _, capture_no_cmd, dep_no_cmd = create_burst_test_capture(
            evidence_no_cmd,
            darwin_arm64_bytes=make_synthetic_macho("arm64", omit_load_command=True),
        )
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture_no_cmd,
                system="aarch64-darwin",
                dependency_archives=dep_no_cmd,
                integrate_closure=True,
                output_dir=self.root / "out_no_cmd",
            )
        self.assertEqual(ctx.exception.code, "INVALID_MACHO")

        # 3. Truncated load command fails closed
        evidence_trunc = self.root / "evidence_trunc"
        _, capture_trunc, dep_trunc = create_burst_test_capture(
            evidence_trunc,
            darwin_arm64_bytes=make_synthetic_macho("arm64", truncate_load_command=True),
        )
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture_trunc,
                system="aarch64-darwin",
                dependency_archives=dep_trunc,
                integrate_closure=True,
                output_dir=self.root / "out_trunc",
            )
        self.assertEqual(ctx.exception.code, "INVALID_MACHO")

    def test_disallowed_wheel_tags_strictly_rejected(self) -> None:
        """[SYNTHETIC] manylinux, musllinux, and x64 Darwin tags are strictly rejected."""
        evidence_dir = self.root / "evidence_disallowed"
        _, capture, dep_archives = create_burst_test_capture(evidence_dir)

        # manylinux rejected on Linux
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture,
                system="x86_64-linux",
                platform_tag="manylinux_2_34_x86_64",
                dependency_archives=dep_archives,
                integrate_closure=True,
                output_dir=self.root / "out_bad_tag_1",
            )
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_PLATFORM")

        # musllinux rejected on Linux
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture,
                system="x86_64-linux",
                platform_tag="musllinux_1_1_x86_64",
                dependency_archives=dep_archives,
                integrate_closure=True,
                output_dir=self.root / "out_bad_tag_2",
            )
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_PLATFORM")

        # x64 Darwin rejected
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture,
                system="aarch64-darwin",
                platform_tag="macosx_13_0_x86_64",
                dependency_archives=dep_archives,
                integrate_closure=True,
                output_dir=self.root / "out_bad_tag_3",
            )
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_PLATFORM")

    def test_global_rejection_when_system_absent_or_other_product(self) -> None:
        """[SYNTHETIC] system=None retains global rejection for Burst; other products always reject native binaries."""
        evidence_dir = self.root / "evidence_global_rej"
        _, capture, dep_archives = create_burst_test_capture(evidence_dir)

        # 1. Burst with native prebuilds but system=None -> UNQUALIFIED_PLATFORM
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                capture,
                system=None,
                dependency_archives=dep_archives,
                integrate_closure=True,
                output_dir=self.root / "out_global_rej",
            )
        self.assertEqual(ctx.exception.code, "UNQUALIFIED_PLATFORM")

        # 2. Stellar Loom with native prebuild and system='x86_64-linux' -> UNQUALIFIED_PLATFORM
        loom_evidence = self.root / "evidence_loom_native"
        from tests.test_wheel_capture import make_test_loom_capture
        _, loom_capture = make_test_loom_capture(
            loom_evidence,
            extra_tar_entries=[(
                "package/native/directory-snapshot/prebuilds/linux-x64-gnu/native-addon-posix-openat-v1.node",
                make_synthetic_elf("x86_64"),
                0o755,
                tarfile.REGTYPE,
            )],
        )
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                "theme-forge-stellar-loom",
                "0.4.0",
                loom_capture,
                system="x86_64-linux",
                output_dir=self.root / "out_loom_native",
            )
        self.assertEqual(ctx.exception.code, "UNQUALIFIED_PLATFORM")

    def test_package_json_platform_constraints_qualification(self) -> None:
        """[SYNTHETIC] Burst package.json constraints are explicitly qualified against system or fail closed."""
        # 1. Positive: matching os & cpu constraint qualifies
        ev_pos = self.root / "evidence_pkg_pos"
        _, cap_pos, dep_pos = create_burst_test_capture(
            ev_pos,
            package_json_extra={"os": ["darwin"], "cpu": ["arm64"]},
        )
        res = build_capture_wheel(
            BURST_PRODUCT_ID,
            "0.6.1",
            cap_pos,
            system="aarch64-darwin",
            dependency_archives=dep_pos,
            integrate_closure=True,
            output_dir=self.root / "out_pkg_pos",
        )
        self.assertEqual(res.tag, "py3-none-macosx_13_0_arm64")

        # 2. Negative: conflicting os constraint fails closed
        ev_neg_os = self.root / "evidence_pkg_neg_os"
        _, cap_neg_os, dep_neg_os = create_burst_test_capture(
            ev_neg_os,
            package_json_extra={"os": ["linux"]},
        )
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                cap_neg_os,
                system="aarch64-darwin",
                dependency_archives=dep_neg_os,
                integrate_closure=True,
                output_dir=self.root / "out_pkg_neg_os",
            )
        self.assertEqual(ctx.exception.code, "UNQUALIFIED_PLATFORM")

        # 3. Negative: conflicting cpu constraint fails closed
        ev_neg_cpu = self.root / "evidence_pkg_neg_cpu"
        _, cap_neg_cpu, dep_neg_cpu = create_burst_test_capture(
            ev_neg_cpu,
            package_json_extra={"cpu": ["x64"]},
        )
        with self.assertRaises(ContractError) as ctx:
            build_capture_wheel(
                BURST_PRODUCT_ID,
                "0.6.1",
                cap_neg_cpu,
                system="aarch64-darwin",
                dependency_archives=dep_neg_cpu,
                integrate_closure=True,
                output_dir=self.root / "out_pkg_neg_cpu",
            )
        self.assertEqual(ctx.exception.code, "UNQUALIFIED_PLATFORM")

    def test_released_loader_info_contract(self) -> None:
        """Verify authentic released loader module details reported for parent."""
        self.assertEqual(RELEASED_LOADER_INFO["loader_module"], "package/dist/directory-snapshot-native.js")
        self.assertEqual(RELEASED_LOADER_INFO["loader_source"], "src/directory-snapshot-native.ts")
        self.assertEqual(RELEASED_LOADER_INFO["loader_export"], "loadDirectorySnapshotNative()")
        self.assertEqual(RELEASED_LOADER_INFO["addon_name"], "native-addon-posix-openat-v1")
        self.assertEqual(len(RELEASED_LOADER_INFO["lazy_invocation_routes"]), 1)
        route = RELEASED_LOADER_INFO["lazy_invocation_routes"][0]
        self.assertIn("createDirectorySnapshot", route["functions"][2])
        self.assertIn("tfsb", route["trigger_entrypoints"][0])


if __name__ == "__main__":
    unittest.main()
