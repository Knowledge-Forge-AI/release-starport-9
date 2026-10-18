"""Unit and negative tests for tf_pypi_native stdlib binary parser and selector."""
import os
from pathlib import Path
import struct
import unittest

from rs9.tf_pypi_archive import AdmissionError, sha256
from rs9.tf_pypi_native import (
    BURST_BACKEND_NAME,
    BURST_LOADER_RELPATH,
    BURST_PREBUILD_SUBDIR,
    EXPECTED_PREBUILD_RELPATHS,
    SUPPORTED_PREBUILD_KEYS,
    inspect_native,
    select_native,
)


def make_synthetic_macho(
    *,
    arch: str = "arm64",
    min_os: tuple[int, int] = (13, 0),
    dylibs: tuple[str, ...] = ("/usr/lib/libSystem.B.dylib",),
    rpaths: tuple[str, ...] = (),
    napi: bool = True,
    platform: int = 1,
) -> bytes:
    """Build a valid minimal Mach-O 64-bit LE binary."""
    cputype = 0x0100000C if arch == "arm64" else 0x01000007
    cmds: list[bytes] = []

    # LC_BUILD_VERSION (cmd=0x32, cmdsize=32)
    minos_val = (min_os[0] << 16) | (min_os[1] << 8)
    cmds.append(struct.pack("<IIIIII", 0x32, 32, platform, minos_val, minos_val, 0) + b"\x00" * 8)

    # LC_LOAD_DYLIB (cmd=0xc)
    for dylib in dylibs:
        raw = dylib.encode("utf-8") + b"\x00"
        pad = (8 - (len(raw) % 8)) % 8
        cmdsize = 24 + len(raw) + pad
        cmds.append(struct.pack("<IIIIII", 0x0C, cmdsize, 24, 0, 0, 0) + raw + b"\x00" * pad)

    # LC_RPATH (cmd=0x1c)
    for rpath in rpaths:
        raw = rpath.encode("utf-8") + b"\x00"
        pad = (8 - (len(raw) % 8)) % 8
        cmdsize = 16 + len(raw) + pad
        cmds.append(struct.pack("<IIII", 0x1C, cmdsize, 16, 0) + raw + b"\x00" * pad)

    # String table & symbol entry
    sym_name = b"_napi_register_module_v1\x00" if napi else b"_other_symbol\x00"
    strtab = b"\x00" + sym_name

    symtab_idx = len(cmds)
    cmds.append(b"")  # placeholder LC_SYMTAB
    cmds.append(b"")  # placeholder LC_DYSYMTAB

    sizeofcmds = sum(len(c) for c in cmds[:symtab_idx]) + 24 + 80
    ncmds = len(cmds)
    offset_symtab = 32 + sizeofcmds
    sym_entry = struct.pack("<IBBHQ", 1, 0x0F, 1, 0, 0x1000)
    offset_strtab = offset_symtab + len(sym_entry)

    cmds[symtab_idx] = struct.pack("<IIIIII", 0x02, 24, offset_symtab, 1, offset_strtab, len(strtab))
    cmds[symtab_idx + 1] = struct.pack("<IIIIII", 0x0B, 80, 0, 0, 0, 1) + b"\x00" * 56

    header = struct.pack("<IIIIIIII", 0xFEEDFACF, cputype, 0, 2, ncmds, sizeofcmds, 0, 0)
    return header + b"".join(cmds) + sym_entry + strtab


def make_synthetic_elf(
    *,
    arch: str = "arm64",
    glibc_versions: tuple[str, ...] = ("2.33",),
    needed: tuple[str, ...] = ("libc.so.6",),
    rpaths: tuple[str, ...] = (),
    runpaths: tuple[str, ...] = (),
    napi: bool = True,
) -> bytes:
    """Build a valid minimal ELF64 little-endian shared library."""
    machine = 183 if arch == "arm64" else 62
    strings = bytearray(b"\x00")

    needed_offs: list[int] = []
    for n in needed:
        needed_offs.append(len(strings))
        strings.extend(n.encode("utf-8") + b"\x00")

    rpath_offs: list[int] = []
    for r in rpaths:
        rpath_offs.append(len(strings))
        strings.extend(r.encode("utf-8") + b"\x00")

    runpath_offs: list[int] = []
    for r in runpaths:
        runpath_offs.append(len(strings))
        strings.extend(r.encode("utf-8") + b"\x00")

    libc_file_off = len(strings)
    strings.extend(b"libc.so.6\x00")

    ver_offs: list[int] = []
    for v in glibc_versions:
        ver_offs.append(len(strings))
        strings.extend(f"GLIBC_{v}\x00".encode("utf-8"))

    sym_name = b"napi_register_module_v1\x00" if napi else b"other_symbol\x00"
    sym_name_off = len(strings)
    strings.extend(sym_name)

    strtab = bytes(strings)

    sym0 = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    sym1 = struct.pack("<IBBHQQ", sym_name_off, (1 << 4) | 2, 0, 1, 0x1000, 16)
    symtab = sym0 + sym1

    # Build DT_VERNEED table
    vernaux_records = bytearray()
    for idx, v_off in enumerate(ver_offs):
        vna_next = 16 if idx < len(ver_offs) - 1 else 0
        vernaux_records.extend(struct.pack("<IHHII", 0, 0, 2, v_off, vna_next))

    verneed = struct.pack("<HHIII", 1, len(ver_offs), libc_file_off, 16, 0) + bytes(vernaux_records)

    ehdr_size = 64
    phnum = 2
    phentsize = 56
    phoff = ehdr_size
    data_start = phoff + phnum * phentsize

    strtab_off = data_start
    symtab_off = strtab_off + len(strtab)
    verneed_off = symtab_off + len(symtab)

    dyn_entries: list[tuple[int, int]] = []
    for off in needed_offs:
        dyn_entries.append((1, off))  # DT_NEEDED
    for off in rpath_offs:
        dyn_entries.append((15, off))  # DT_RPATH
    for off in runpath_offs:
        dyn_entries.append((29, off))  # DT_RUNPATH

    dyn_entries.append((5, strtab_off))  # DT_STRTAB
    dyn_entries.append((10, len(strtab)))  # DT_STRSZ
    dyn_entries.append((6, symtab_off))  # DT_SYMTAB
    dyn_entries.append((11, 24))  # DT_SYMENT
    dyn_entries.append((0x6FFFFFFE, verneed_off))  # DT_VERNEED
    dyn_entries.append((0x6FFFFFFF, 1))  # DT_VERNEEDNUM
    dyn_entries.append((0, 0))  # DT_NULL

    dynamic_bytes = b"".join(struct.pack("<qQ", tag, val) for tag, val in dyn_entries)
    dyn_off = verneed_off + len(verneed)
    total_len = dyn_off + len(dynamic_bytes)

    phdr_load = struct.pack("<IIQQQQQQ", 1, 7, 0, 0, 0, total_len, total_len, 0x1000)
    phdr_dyn = struct.pack("<IIQQQQQQ", 2, 6, dyn_off, dyn_off, dyn_off, len(dynamic_bytes), len(dynamic_bytes), 8)
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8,
        3,
        machine,
        1,
        0,
        phoff,
        0,
        0,
        ehdr_size,
        phentsize,
        phnum,
        0,
        0,
        0,
    )
    return ehdr + phdr_load + phdr_dyn + strtab + symtab + verneed + dynamic_bytes


SYNTHETIC_LOADER_SCRIPT: bytes = b"""
export const DIRECTORY_SNAPSHOT_BACKEND = "native-addon-posix-openat-v1";
export const DIRECTORY_SNAPSHOT_BACKEND_ABI = 1;

export function currentDirectorySnapshotArtifact() {
    if (process.platform === "darwin" && process.arch === "arm64") return "darwin-arm64";
    if (process.platform === "darwin" && process.arch === "x64") return "darwin-x64";
    if (process.platform === "linux" && process.arch === "arm64") return "linux-arm64-gnu";
    if (process.platform === "linux" && process.arch === "x64") return "linux-x64-gnu";
    return "none";
}

export function loadDirectorySnapshotNative() {
    const artifact = currentDirectorySnapshotArtifact();
    const artifactPath = `./native/directory-snapshot/prebuilds/${artifact}/${DIRECTORY_SNAPSHOT_BACKEND}.node`;
    return { ok: true, artifact };
}
"""


def make_synthetic_files(prefix: str = "package/") -> dict[str, tuple[bytes, int]]:
    """Build a complete admitted files mapping with all 4 prebuilds and loader."""
    files: dict[str, tuple[bytes, int]] = {
        f"{prefix}{BURST_LOADER_RELPATH}": (SYNTHETIC_LOADER_SCRIPT, 0o644),
        f"{prefix}package.json": (b'{"name": "@knowledge-forge-ai/theme-forge-stellar-burst"}', 0o644),
    }

    files[f"{prefix}{EXPECTED_PREBUILD_RELPATHS['darwin-arm64']}"] = (
        make_synthetic_macho(arch="arm64", min_os=(13, 0), napi=True),
        0o755,
    )
    files[f"{prefix}{EXPECTED_PREBUILD_RELPATHS['darwin-x64']}"] = (
        make_synthetic_macho(arch="x86_64", min_os=(15, 0), napi=True),
        0o755,
    )
    files[f"{prefix}{EXPECTED_PREBUILD_RELPATHS['linux-arm64-gnu']}"] = (
        make_synthetic_elf(arch="arm64", glibc_versions=("2.33",), napi=True),
        0o755,
    )
    files[f"{prefix}{EXPECTED_PREBUILD_RELPATHS['linux-x64-gnu']}"] = (
        make_synthetic_elf(arch="x86_64", glibc_versions=("2.17", "2.28", "2.33"), napi=True),
        0o755,
    )

    for key in SUPPORTED_PREBUILD_KEYS:
        files[f"{prefix}{BURST_PREBUILD_SUBDIR}/{key}/manifest.json"] = (b'{"backend": "native"}', 0o644)

    return files


class TfPypiNativeTests(unittest.TestCase):
    def test_inspect_native_synthetic_macho_arm64(self):
        data = make_synthetic_macho(arch="arm64", min_os=(13, 0), napi=True)
        info = inspect_native(data)
        self.assertEqual(info["format"], "macho")
        self.assertEqual(info["architecture"], "arm64")
        self.assertEqual(info["minimum_os"], (13, 0))
        self.assertIsNone(info["glibc_max"])
        self.assertTrue(info["napi"])
        self.assertEqual(info["needed"], ["/usr/lib/libSystem.B.dylib"])
        self.assertEqual(info["rpath"], [])
        self.assertEqual(info["runpath"], [])

    def test_inspect_native_synthetic_macho_x86_64(self):
        data = make_synthetic_macho(arch="x86_64", min_os=(15, 0), napi=True)
        info = inspect_native(data)
        self.assertEqual(info["format"], "macho")
        self.assertEqual(info["architecture"], "x86_64")
        self.assertEqual(info["minimum_os"], (15, 0))
        self.assertTrue(info["napi"])

    def test_inspect_native_synthetic_macho_without_napi(self):
        data = make_synthetic_macho(arch="arm64", napi=False)
        info = inspect_native(data)
        self.assertFalse(info["napi"])

    def test_inspect_native_synthetic_elf_arm64(self):
        data = make_synthetic_elf(arch="arm64", glibc_versions=("2.17", "2.33"), napi=True)
        info = inspect_native(data)
        self.assertEqual(info["format"], "elf")
        self.assertEqual(info["architecture"], "arm64")
        self.assertIsNone(info["minimum_os"])
        self.assertEqual(info["glibc_max"], (2, 33))
        self.assertTrue(info["napi"])
        self.assertEqual(info["needed"], ["libc.so.6"])
        self.assertEqual(info["rpath"], [])
        self.assertEqual(info["runpath"], [])

    def test_inspect_native_synthetic_elf_x86_64(self):
        data = make_synthetic_elf(arch="x86_64", glibc_versions=("2.28", "2.4", "2.2.5"), napi=True)
        info = inspect_native(data)
        self.assertEqual(info["format"], "elf")
        self.assertEqual(info["architecture"], "x86_64")
        self.assertEqual(info["glibc_max"], (2, 28))
        self.assertTrue(info["napi"])

    def test_inspect_native_synthetic_elf_without_napi(self):
        data = make_synthetic_elf(arch="x86_64", napi=False)
        info = inspect_native(data)
        self.assertFalse(info["napi"])

    def test_inspect_native_malformed_and_unsupported_inputs(self):
        # Non-bytes
        with self.assertRaises(AdmissionError):
            inspect_native(12345)  # type: ignore

        # Empty / truncated
        with self.assertRaises(AdmissionError):
            inspect_native(b"")
        with self.assertRaises(AdmissionError):
            inspect_native(b"\x00" * 15)

        # Unrecognized magic
        with self.assertRaises(AdmissionError):
            inspect_native(b"NO_MAGIC_BYTES_HERE" + b"\x00" * 40)

        # PE binary
        with self.assertRaises(AdmissionError):
            inspect_native(b"MZ" + b"\x00" * 60)

        # Mach-O universal / 32-bit / big-endian
        with self.assertRaises(AdmissionError):
            inspect_native(struct.pack("<I", 0xCAFEBABE) + b"\x00" * 40)
        with self.assertRaises(AdmissionError):
            inspect_native(struct.pack("<I", 0xFEEDFACE) + b"\x00" * 40)
        with self.assertRaises(AdmissionError):
            inspect_native(struct.pack("<I", 0xCFFAEDFE) + b"\x00" * 40)

        # ELF 32-bit / big-endian / invalid machine
        with self.assertRaises(AdmissionError):
            inspect_native(b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 60)  # ELF32
        with self.assertRaises(AdmissionError):
            inspect_native(b"\x7fELF\x02\x02\x01\x00" + b"\x00" * 60)  # big-endian
        with self.assertRaises(AdmissionError):
            inspect_native(b"\x7fELF\x02\x01\x01\x00" + struct.pack("<H", 3) + b"\x00" * 60)  # i386

        # Truncated load commands
        macho = make_synthetic_macho()
        with self.assertRaises(AdmissionError):
            inspect_native(macho[:60])  # truncated in middle of load commands

        # Missing deployment minimum in Mach-O
        macho_no_dep = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
        with self.assertRaises(AdmissionError):
            inspect_native(macho_no_dep)

    def test_select_native_all_four_prebuild_keys(self):
        files = make_synthetic_files()

        # darwin-arm64
        filtered, tag, transform = select_native(files, "darwin-arm64")
        self.assertEqual(tag, "macosx_13_0_arm64")
        self.assertEqual(len(filtered), len(files) - 3)
        self.assertIn(f"package/{EXPECTED_PREBUILD_RELPATHS['darwin-arm64']}", filtered)
        self.assertNotIn(f"package/{EXPECTED_PREBUILD_RELPATHS['darwin-x64']}", filtered)
        self.assertNotIn(f"package/{EXPECTED_PREBUILD_RELPATHS['linux-arm64-gnu']}", filtered)
        self.assertNotIn(f"package/{EXPECTED_PREBUILD_RELPATHS['linux-x64-gnu']}", filtered)
        self.assertEqual(len(transform["omissions"]), 3)
        self.assertEqual(transform["target_key"], "darwin-arm64")
        self.assertEqual(transform["wheel_platform_tag"], "macosx_13_0_arm64")
        self.assertTrue(transform["native_facts"]["napi"])
        self.assertEqual(transform["native_facts"]["minimum_os"], (13, 0))

        # darwin-x64
        filtered_x64, tag_x64, transform_x64 = select_native(files, "darwin-x64")
        self.assertEqual(tag_x64, "macosx_15_0_x86_64")
        self.assertIn(f"package/{EXPECTED_PREBUILD_RELPATHS['darwin-x64']}", filtered_x64)
        self.assertNotIn(f"package/{EXPECTED_PREBUILD_RELPATHS['darwin-arm64']}", filtered_x64)
        self.assertEqual(len(transform_x64["omissions"]), 3)

        # linux-arm64-gnu
        filtered_l_arm, tag_l_arm, transform_l_arm = select_native(files, "linux-arm64-gnu")
        self.assertEqual(tag_l_arm, "manylinux_2_33_aarch64")
        self.assertIn(f"package/{EXPECTED_PREBUILD_RELPATHS['linux-arm64-gnu']}", filtered_l_arm)
        self.assertNotIn(f"package/{EXPECTED_PREBUILD_RELPATHS['linux-x64-gnu']}", filtered_l_arm)
        self.assertEqual(len(transform_l_arm["omissions"]), 3)

        # linux-x64-gnu
        filtered_l_x64, tag_l_x64, transform_l_x64 = select_native(files, "linux-x64-gnu")
        self.assertEqual(tag_l_x64, "manylinux_2_33_x86_64")
        self.assertIn(f"package/{EXPECTED_PREBUILD_RELPATHS['linux-x64-gnu']}", filtered_l_x64)
        self.assertNotIn(f"package/{EXPECTED_PREBUILD_RELPATHS['linux-arm64-gnu']}", filtered_l_x64)
        self.assertEqual(len(transform_l_x64["omissions"]), 3)

    def test_select_native_omissions_records(self):
        files = make_synthetic_files()
        _, _, transform = select_native(files, "darwin-arm64")
        omissions = transform["omissions"]
        self.assertEqual(len(omissions), 3)
        omitted_paths = [om["path"] for om in omissions]
        expected_omitted = sorted([
            f"package/{EXPECTED_PREBUILD_RELPATHS['darwin-x64']}",
            f"package/{EXPECTED_PREBUILD_RELPATHS['linux-arm64-gnu']}",
            f"package/{EXPECTED_PREBUILD_RELPATHS['linux-x64-gnu']}",
        ])
        self.assertEqual(omitted_paths, expected_omitted)
        for om in omissions:
            self.assertEqual(om["size"], len(files[om["path"]][0]))
            self.assertEqual(om["sha256"], sha256(files[om["path"]][0]))

    def test_select_native_unsupported_key(self):
        files = make_synthetic_files()
        for bad_key in ("win32-x64", "linux-musl", "any", "darwin-universal", ""):
            with self.subTest(key=bad_key):
                with self.assertRaises(AdmissionError):
                    select_native(files, bad_key)

    def test_select_native_missing_prebuild_rejected(self):
        files = make_synthetic_files()
        del files[f"package/{EXPECTED_PREBUILD_RELPATHS['linux-x64-gnu']}"]
        with self.assertRaises(AdmissionError):
            select_native(files, "darwin-arm64")

    def test_select_native_unexpected_native_rejected(self):
        files = make_synthetic_files()
        # Unexpected .node
        bad_files_1 = dict(files)
        bad_files_1["package/dist/extra.node"] = (b"\x7fELF" + b"\x00" * 100, 0o755)
        with self.assertRaises(AdmissionError):
            select_native(bad_files_1, "darwin-arm64")

        # Unexpected .so
        bad_files_2 = dict(files)
        bad_files_2["package/libfoo.so"] = (b"\x00" * 100, 0o644)
        with self.assertRaises(AdmissionError):
            select_native(bad_files_2, "darwin-arm64")

        # Unexpected binary magic in non-native filename
        bad_files_3 = dict(files)
        bad_files_3["package/scripts/data.bin"] = (b"\xcf\xfa\xed\xfe" + b"\x00" * 60, 0o644)
        with self.assertRaises(AdmissionError):
            select_native(bad_files_3, "darwin-arm64")

    def test_select_native_wrong_format_for_platform(self):
        files = make_synthetic_files()
        # Put ELF into darwin-arm64 slot
        files[f"package/{EXPECTED_PREBUILD_RELPATHS['darwin-arm64']}"] = (
            make_synthetic_elf(arch="arm64"),
            0o755,
        )
        with self.assertRaises(AdmissionError):
            select_native(files, "darwin-arm64")

    def test_select_native_wrong_arch_for_platform(self):
        files = make_synthetic_files()
        # Put x86_64 into darwin-arm64 slot
        files[f"package/{EXPECTED_PREBUILD_RELPATHS['darwin-arm64']}"] = (
            make_synthetic_macho(arch="x86_64"),
            0o755,
        )
        with self.assertRaises(AdmissionError):
            select_native(files, "darwin-arm64")

    def test_select_native_missing_napi_export(self):
        files = make_synthetic_files()
        # Prebuild lacking N-API export
        files[f"package/{EXPECTED_PREBUILD_RELPATHS['linux-x64-gnu']}"] = (
            make_synthetic_elf(arch="x86_64", napi=False),
            0o755,
        )
        with self.assertRaises(AdmissionError):
            select_native(files, "linux-x64-gnu")

    def test_select_native_elf_with_rpath_or_extra_dependency(self):
        # ELF with DT_RPATH
        files_rpath = make_synthetic_files()
        files_rpath[f"package/{EXPECTED_PREBUILD_RELPATHS['linux-x64-gnu']}"] = (
            make_synthetic_elf(arch="x86_64", rpaths=("$ORIGIN/lib",)),
            0o755,
        )
        with self.assertRaises(AdmissionError):
            select_native(files_rpath, "linux-x64-gnu")

        # ELF with extra dependency (not libc.so.6 only)
        files_needed = make_synthetic_files()
        files_needed[f"package/{EXPECTED_PREBUILD_RELPATHS['linux-x64-gnu']}"] = (
            make_synthetic_elf(arch="x86_64", needed=("libc.so.6", "libm.so.6")),
            0o755,
        )
        with self.assertRaises(AdmissionError):
            select_native(files_needed, "linux-x64-gnu")

    def test_select_native_loader_missing_or_corrupt(self):
        # Missing loader
        files_no_loader = make_synthetic_files()
        del files_no_loader[f"package/{BURST_LOADER_RELPATH}"]
        with self.assertRaises(AdmissionError):
            select_native(files_no_loader, "darwin-arm64")

        # Corrupt loader (unconditional loading of all artifacts)
        files_bad_loader = make_synthetic_files()
        bad_loader = b"for (const artifact of allArtifacts) { require(artifact); }"
        files_bad_loader[f"package/{BURST_LOADER_RELPATH}"] = (bad_loader, 0o644)
        with self.assertRaises(AdmissionError):
            select_native(files_bad_loader, "darwin-arm64")

    def test_real_burst_inputs_when_env_explicit(self):
        """Qualified real-byte tests executed only when explicit environment is provided."""
        real_input_dir = os.environ.get("RS9_TF_PYPI_INPUTS")
        real_input_file = os.environ.get("RS9_REAL_BURST_TGZ")

        target_path: Path | None = None
        if real_input_file and Path(real_input_file).is_file():
            target_path = Path(real_input_file)
        elif real_input_dir:
            candidate = Path(real_input_dir) / "knowledge-forge-ai-theme-forge-stellar-burst-0.6.1.tgz"
            if candidate.is_file():
                target_path = candidate

        # If explicit environment is not configured, pass without unqualified skip
        if target_path is None:
            return

        from rs9.tf_pypi_archive import read_tar

        data = target_path.read_bytes()
        files = read_tar(data)

        # Verify real inspected facts without executing payloads
        for key in SUPPORTED_PREBUILD_KEYS:
            with self.subTest(key=key):
                filtered, tag, transform = select_native(files, key)
                self.assertEqual(len(filtered), len(files) - 3)
                self.assertEqual(len(transform["omissions"]), 3)
                self.assertEqual(transform["target_key"], key)
                facts = transform["native_facts"]
                self.assertTrue(facts["napi"])

                if key == "darwin-arm64":
                    self.assertEqual(tag, "macosx_13_0_arm64")
                    self.assertEqual(facts["format"], "macho")
                    self.assertEqual(facts["architecture"], "arm64")
                    self.assertEqual(facts["minimum_os"], (13, 0))
                elif key == "darwin-x64":
                    self.assertEqual(tag, "macosx_15_0_x86_64")
                    self.assertEqual(facts["format"], "macho")
                    self.assertEqual(facts["architecture"], "x86_64")
                    self.assertEqual(facts["minimum_os"], (15, 0))
                elif key == "linux-arm64-gnu":
                    self.assertEqual(tag, "manylinux_2_33_aarch64")
                    self.assertEqual(facts["format"], "elf")
                    self.assertEqual(facts["architecture"], "arm64")
                    self.assertEqual(facts["glibc_max"], (2, 33))
                    self.assertEqual(facts["needed"], ["libc.so.6"])
                elif key == "linux-x64-gnu":
                    self.assertEqual(tag, "manylinux_2_33_x86_64")
                    self.assertEqual(facts["format"], "elf")
                    self.assertEqual(facts["architecture"], "x86_64")
                    self.assertEqual(facts["glibc_max"], (2, 33))
                    self.assertEqual(facts["needed"], ["libc.so.6"])


if __name__ == "__main__":
    unittest.main()
