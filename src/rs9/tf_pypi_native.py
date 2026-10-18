"""Deterministic stdlib binary parser and native payload selector for Theme Forge Stellar Burst."""
from __future__ import annotations

import re
import struct
from typing import Any, Mapping

from rs9.tf_pypi_archive import fail, sha256

BURST_PRODUCT_ID: str = "theme-forge-stellar-burst"
BURST_BACKEND_NAME: str = "native-addon-posix-openat-v1"
BURST_PREBUILD_SUBDIR: str = "native/directory-snapshot/prebuilds"
BURST_LOADER_RELPATH: str = "dist/directory-snapshot-native.js"

SUPPORTED_PREBUILD_KEYS: tuple[str, ...] = (
    "darwin-arm64",
    "darwin-x64",
    "linux-arm64-gnu",
    "linux-x64-gnu",
)

EXPECTED_PREBUILD_RELPATHS: dict[str, str] = {
    key: f"{BURST_PREBUILD_SUBDIR}/{key}/{BURST_BACKEND_NAME}.node"
    for key in SUPPORTED_PREBUILD_KEYS
}

NATIVE_MAGIC: tuple[bytes, ...] = (
    b"\x7fELF",
    b"MZ",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
)

NATIVE_EXTENSIONS: tuple[str, ...] = (
    ".node",
    ".so",
    ".dylib",
    ".dll",
    ".exe",
    ".a",
)

# Mach-O constants
_MACHO_MAGIC_64_LE = 0xFEEDFACF
_MACHO_MAGIC_64_BE = 0xCFFAEDFE
_MACHO_MAGIC_32_LE = 0xFEEDFACE
_MACHO_MAGIC_32_BE = 0xCEFAEDFE
_MACHO_FAT_MAGICS = (0xCAFEBABE, 0xBEBAFECA, 0xCAFEBABF, 0xBFBAFECA)

_CPU_TYPE_ARM64 = 0x0100000C
_CPU_TYPE_X86_64 = 0x01000007

_LC_BUILD_VERSION = 0x32
_LC_VERSION_MIN_MACOSX = 0x24
_LC_LOAD_DYLIB = 0x0C
_LC_LOAD_WEAK_DYLIB = 0x80000018
_LC_REEXPORT_DYLIB = 0x8000001F
_LC_RPATH = 0x1C
_LC_RPATH_64 = 0x8000001C
_LC_SYMTAB = 0x02
_LC_DYSYMTAB = 0x0B
_LC_DYLD_INFO = 0x22
_LC_DYLD_INFO_ONLY = 0x80000022
_LC_DYLD_EXPORTS_TRIE = 0x80000033
_PLATFORM_MACOS = 1

# ELF constants
_ELF_MAGIC = b"\x7fELF"
_ELFCLASS64 = 2
_ELFDATA2LSB = 1
_EV_CURRENT = 1
_ET_EXEC = 2
_ET_DYN = 3
_EM_X86_64 = 62
_EM_AARCH64 = 183

_PT_LOAD = 1
_PT_DYNAMIC = 2

_DT_NULL = 0
_DT_NEEDED = 1
_DT_HASH = 4
_DT_STRTAB = 5
_DT_SYMTAB = 6
_DT_STRSZ = 10
_DT_SYMENT = 11
_DT_RPATH = 15
_DT_RUNPATH = 29
_DT_VERNEED = 0x6FFFFFFE
_DT_VERNEEDNUM = 0x6FFFFFFF

_SHT_STRTAB = 3
_SHT_DYNSYM = 11
_SHT_GNU_VERNEED = 0x6FFFFFFE

_MAX_ENTRIES = 10_000


def _parse_elf_verneeds(
    data: bytes,
    start_offset: int,
    count: int,
    get_str_func: Any,
) -> dict[str, list[str]]:
    """Parse ELF DT_VERNEED structures with loop and bounds protection."""
    if count <= 0 or count > _MAX_ENTRIES:
        fail("MALFORMED")

    verneeds: dict[str, list[str]] = {}
    current_off = start_offset
    visited_verneed: set[int] = set()

    for i in range(count):
        if current_off < 0 or current_off + 16 > len(data):
            fail("TRUNCATED")
        if current_off in visited_verneed:
            fail("MALFORMED")
        visited_verneed.add(current_off)

        vn_version, vn_cnt, vn_file, vn_aux, vn_next = struct.unpack_from("<HHIII", data, current_off)
        if vn_version != 1 or vn_cnt < 0 or vn_cnt > _MAX_ENTRIES:
            fail("MALFORMED")

        filename = get_str_func(vn_file)
        if not filename:
            fail("MALFORMED")

        aux_names: list[str] = []
        if vn_cnt > 0:
            if vn_aux == 0:
                fail("MALFORMED")
            aux_off = current_off + vn_aux
            visited_aux: set[int] = set()
            for j in range(vn_cnt):
                if aux_off < 0 or aux_off + 16 > len(data):
                    fail("TRUNCATED")
                if aux_off in visited_aux:
                    fail("MALFORMED")
                visited_aux.add(aux_off)

                vna_hash, vna_flags, vna_other, vna_name, vna_next = struct.unpack_from("<IHHII", data, aux_off)
                ver_name = get_str_func(vna_name)
                if not ver_name:
                    fail("MALFORMED")
                aux_names.append(ver_name)

                if j < vn_cnt - 1:
                    if vna_next == 0:
                        fail("TRUNCATED")
                    vna_delta = vna_next if vna_next < 0x80000000 else vna_next - 0x100000000
                    aux_off += vna_delta

        verneeds.setdefault(filename, []).extend(aux_names)

        if i < count - 1:
            if vn_next == 0:
                fail("TRUNCATED")
            vn_delta = vn_next if vn_next < 0x80000000 else vn_next - 0x100000000
            current_off += vn_delta

    return verneeds


def _inspect_elf(data: bytes) -> dict[str, Any]:
    """Inspect and extract facts from ELF64 little-endian binary data."""
    if len(data) < 64:
        fail("TRUNCATED")

    ei_class = data[4]
    ei_data = data[5]
    ei_version = data[6]

    if ei_class == 1:
        fail("UNSUPPORTED_FORMAT")
    if ei_class != _ELFCLASS64:
        fail("UNSUPPORTED_FORMAT")
    if ei_data == 2:
        fail("UNSUPPORTED_FORMAT")
    if ei_data != _ELFDATA2LSB:
        fail("UNSUPPORTED_FORMAT")
    if ei_version != _EV_CURRENT:
        fail("MALFORMED")

    (
        e_ident,
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
    ) = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)

    if e_version != _EV_CURRENT or e_ehsize < 64:
        fail("MALFORMED")
    if e_type not in (_ET_EXEC, _ET_DYN):
        fail("UNSUPPORTED_FORMAT")

    if e_machine == _EM_AARCH64:
        arch = "arm64"
    elif e_machine == _EM_X86_64:
        arch = "x86_64"
    else:
        fail("UNSUPPORTED_ARCH")

    if e_phnum <= 0 or e_phnum > _MAX_ENTRIES or e_phentsize < 56:
        fail("MALFORMED")

    ph_table_end = e_phoff + e_phnum * e_phentsize
    if ph_table_end > len(data):
        fail("TRUNCATED")

    load_segments: list[tuple[int, int, int, int]] = []
    dyn_segment: tuple[int, int] | None = None

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
            "<IIQQQQQQ", data, off
        )
        if p_type == _PT_LOAD:
            if p_filesz > p_memsz or p_offset + p_filesz > len(data):
                fail("TRUNCATED")
            load_segments.append((p_vaddr, p_memsz, p_offset, p_filesz))
        elif p_type == _PT_DYNAMIC:
            if dyn_segment is not None:
                fail("MALFORMED")
            if p_offset + p_filesz > len(data):
                fail("TRUNCATED")
            dyn_segment = (p_offset, p_filesz)

    if dyn_segment is None:
        fail("MALFORMED")

    def vaddr_to_offset(vaddr: int, size: int = 1) -> int:
        for p_vaddr, p_memsz, p_offset, p_filesz in load_segments:
            if p_vaddr <= vaddr and vaddr + size <= p_vaddr + p_filesz:
                return p_offset + (vaddr - p_vaddr)
        fail("MALFORMED")

    dyn_offset, dyn_filesz = dyn_segment
    if dyn_filesz % 16 != 0:
        fail("MALFORMED")
    num_dyn = dyn_filesz // 16
    if num_dyn > _MAX_ENTRIES:
        fail("MALFORMED")

    needed_offsets: list[int] = []
    rpath_offsets: list[int] = []
    runpath_offsets: list[int] = []
    strtab_vaddr: int | None = None
    strtab_sz: int | None = None
    symtab_vaddr: int | None = None
    verneed_vaddr: int | None = None
    verneed_num: int | None = None
    hash_vaddr: int | None = None

    for i in range(num_dyn):
        entry_off = dyn_offset + i * 16
        d_tag, d_val = struct.unpack_from("<qQ", data, entry_off)
        if d_tag == _DT_NULL:
            break
        elif d_tag == _DT_NEEDED:
            needed_offsets.append(d_val)
        elif d_tag == _DT_RPATH:
            rpath_offsets.append(d_val)
        elif d_tag == _DT_RUNPATH:
            runpath_offsets.append(d_val)
        elif d_tag == _DT_STRTAB:
            strtab_vaddr = d_val
        elif d_tag == _DT_STRSZ:
            strtab_sz = d_val
        elif d_tag == _DT_SYMTAB:
            symtab_vaddr = d_val
        elif d_tag == _DT_VERNEED:
            verneed_vaddr = d_val
        elif d_tag == _DT_VERNEEDNUM:
            verneed_num = d_val
        elif d_tag == _DT_HASH:
            hash_vaddr = d_val
    else:
        fail("MALFORMED")

    if strtab_vaddr is None or strtab_sz is None:
        fail("MALFORMED")
    if strtab_sz < 1 or strtab_sz > len(data):
        fail("MALFORMED")

    strtab_off = vaddr_to_offset(strtab_vaddr, strtab_sz)
    if strtab_off + strtab_sz > len(data):
        fail("TRUNCATED")
    strtab_data = data[strtab_off : strtab_off + strtab_sz]
    if strtab_data[0] != 0:
        fail("MALFORMED")

    def get_str(off: int) -> str:
        if off < 0 or off >= len(strtab_data):
            fail("MALFORMED")
        null_pos = strtab_data.find(b"\x00", off)
        if null_pos == -1:
            fail("MALFORMED")
        raw = strtab_data[off:null_pos]
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            fail("MALFORMED")

    needed: list[str] = []
    for off in needed_offsets:
        s = get_str(off)
        if not s:
            fail("MALFORMED")
        needed.append(s)

    rpath: list[str] = []
    for off in rpath_offsets:
        s = get_str(off)
        for part in s.split(":"):
            if part:
                rpath.append(part)

    runpath: list[str] = []
    for off in runpath_offsets:
        s = get_str(off)
        for part in s.split(":"):
            if part:
                runpath.append(part)

    version_needs: dict[str, list[str]] = {}
    if verneed_vaddr is not None or verneed_num is not None:
        if verneed_vaddr is None or verneed_num is None:
            fail("MALFORMED")
        verneed_off = vaddr_to_offset(verneed_vaddr)
        version_needs = _parse_elf_verneeds(data, verneed_off, verneed_num, get_str)

    # Section fallback if present
    if not version_needs and verneed_vaddr is None and e_shoff != 0 and e_shnum > 0:
        if e_shentsize < 64 or e_shnum > _MAX_ENTRIES:
            fail("MALFORMED")
        if e_shoff + e_shnum * e_shentsize > len(data):
            fail("TRUNCATED")
        for i in range(e_shnum):
            entry_off = e_shoff + i * e_shentsize
            (
                sh_name,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                sh_link,
                sh_info,
                sh_addralign,
                sh_entsize,
            ) = struct.unpack_from("<IIQQQQIIQQ", data, entry_off)
            if sh_type == _SHT_GNU_VERNEED:
                if sh_link >= e_shnum:
                    fail("MALFORMED")
                str_entry_off = e_shoff + sh_link * e_shentsize
                _, s_type, _, _, s_offset, s_size, _, _, _, _ = struct.unpack_from(
                    "<IIQQQQIIQQ", data, str_entry_off
                )
                if s_type != _SHT_STRTAB or s_offset + s_size > len(data):
                    fail("MALFORMED")
                sec_strtab = data[s_offset : s_offset + s_size]

                def sec_get_str(off: int) -> str:
                    if off < 0 or off >= len(sec_strtab):
                        fail("MALFORMED")
                    pos = sec_strtab.find(b"\x00", off)
                    if pos == -1:
                        fail("MALFORMED")
                    try:
                        return sec_strtab[off:pos].decode("utf-8")
                    except UnicodeDecodeError:
                        fail("MALFORMED")

                if sh_offset + sh_size > len(data):
                    fail("TRUNCATED")
                version_needs = _parse_elf_verneeds(data, sh_offset, sh_info, sec_get_str)
                break

    # Determine glibc_max
    glibc_versions: list[tuple[int, ...]] = []
    for ver_list in version_needs.values():
        for ver_str in ver_list:
            m = re.match(r"^GLIBC_(\d+(?:\.\d+)*)$", ver_str)
            if m:
                parts = tuple(int(x) for x in m.group(1).split("."))
                glibc_versions.append(parts)

    glibc_max: tuple[int, int] | None = None
    if glibc_versions:
        max_tuple = max(glibc_versions)
        if len(max_tuple) >= 2:
            glibc_max = (max_tuple[0], max_tuple[1])
        else:
            glibc_max = (max_tuple[0], 0)

    # Determine napi export
    napi = False
    # Scan from section headers SHT_DYNSYM if present
    if e_shoff != 0 and e_shnum > 0:
        for i in range(e_shnum):
            entry_off = e_shoff + i * e_shentsize
            (
                sh_name,
                sh_type,
                sh_flags,
                sh_addr,
                sec_offset,
                sec_size,
                sh_link,
                sh_info,
                sh_addralign,
                sh_entsize,
            ) = struct.unpack_from("<IIQQQQIIQQ", data, entry_off)
            if sh_type == _SHT_DYNSYM and sh_entsize >= 24:
                if sh_link >= e_shnum:
                    fail("MALFORMED")
                str_hdr = e_shoff + sh_link * e_shentsize
                _, _, _, _, str_off, str_sz, _, _, _, _ = struct.unpack_from(
                    "<IIQQQQIIQQ", data, str_hdr
                )
                if str_off + str_sz > len(data):
                    fail("TRUNCATED")
                dyn_strtab = data[str_off : str_off + str_sz]
                num_syms = sec_size // sh_entsize
                for s_i in range(num_syms):
                    sym_off = sec_offset + s_i * sh_entsize
                    if sym_off + 24 > len(data):
                        break
                    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
                        "<IBBHQQ", data, sym_off
                    )
                    st_bind = st_info >> 4
                    if st_shndx != 0 and st_shndx != 0xFFF1 and st_bind in (1, 2):
                        if st_name < len(dyn_strtab):
                            nul = dyn_strtab.find(b"\x00", st_name)
                            if nul != -1:
                                sym_name = dyn_strtab[st_name:nul].decode("utf-8", errors="replace")
                                if sym_name in ("napi_register_module_v1", "_napi_register_module_v1"):
                                    napi = True
                                    break
                break

    # Dynamic symbol table fallback if section headers absent
    if not napi and symtab_vaddr is not None:
        try:
            sym_file_off = vaddr_to_offset(symtab_vaddr)
            # Determine count from DT_HASH if available, otherwise bounded scan
            sym_count = _MAX_ENTRIES
            if hash_vaddr is not None:
                hash_off = vaddr_to_offset(hash_vaddr)
                if hash_off + 8 <= len(data):
                    _, nchain = struct.unpack_from("<II", data, hash_off)
                    if 0 < nchain <= _MAX_ENTRIES:
                        sym_count = nchain
            for s_i in range(sym_count):
                curr = sym_file_off + s_i * 24
                if curr + 24 > len(data):
                    break
                st_name, st_info, st_other, st_shndx, st_val, st_sz = struct.unpack_from("<IBBHQQ", data, curr)
                if st_name >= len(strtab_data):
                    break
                st_bind = st_info >> 4
                if st_shndx != 0 and st_shndx != 0xFFF1 and st_bind in (1, 2):
                    nul = strtab_data.find(b"\x00", st_name)
                    if nul != -1:
                        sym_name = strtab_data[st_name:nul].decode("utf-8", errors="replace")
                        if sym_name in ("napi_register_module_v1", "_napi_register_module_v1"):
                            napi = True
                            break
        except (struct.error, IndexError):
            fail("MALFORMED")

    return {
        "format": "elf",
        "architecture": arch,
        "napi": napi,
        "minimum_os": None,
        "glibc_max": glibc_max,
        "needed": needed,
        "rpath": rpath,
        "runpath": runpath,
        "rpath_runpath": rpath + runpath,
        "arch": arch,
    }


def _inspect_macho(data: bytes) -> dict[str, Any]:
    """Inspect and extract facts from Mach-O 64-bit little-endian binary data."""
    if len(data) < 32:
        fail("TRUNCATED")

    magic = struct.unpack_from("<I", data, 0)[0]
    if magic in _MACHO_FAT_MAGICS:
        fail("UNSUPPORTED_FORMAT")
    if magic in (_MACHO_MAGIC_32_LE, _MACHO_MAGIC_32_BE):
        fail("UNSUPPORTED_FORMAT")
    if magic == _MACHO_MAGIC_64_BE:
        fail("UNSUPPORTED_FORMAT")
    if magic != _MACHO_MAGIC_64_LE:
        fail("MALFORMED")

    cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
        "<iiIIIII", data, 4
    )

    if cputype == _CPU_TYPE_ARM64:
        arch = "arm64"
    elif cputype == _CPU_TYPE_X86_64:
        arch = "x86_64"
    else:
        fail("UNSUPPORTED_ARCH")

    if 32 + sizeofcmds > len(data) or ncmds > sizeofcmds // 8 or ncmds > _MAX_ENTRIES:
        fail("MALFORMED")

    minimum_os: tuple[int, int] | None = None
    needed: list[str] = []
    rpath: list[str] = []
    symtab_cmd: tuple[int, int, int, int] | None = None
    dysymtab_cmd: tuple[int, int, int, int, int, int] | None = None
    export_trie_range: tuple[int, int] | None = None

    offset = 32
    for _ in range(ncmds):
        if offset + 8 > 32 + sizeofcmds:
            fail("TRUNCATED")
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmdsize < 8 or cmdsize % 4 != 0 or offset + cmdsize > 32 + sizeofcmds:
            fail("MALFORMED")

        if cmd == _LC_BUILD_VERSION:
            if cmdsize < 24:
                fail("MALFORMED")
            platform, minos, sdk, ntools = struct.unpack_from("<IIII", data, offset + 8)
            if platform != _PLATFORM_MACOS:
                fail("UNSUPPORTED_PLATFORM")
            major = (minos >> 16) & 0xFFFF
            minor = (minos >> 8) & 0xFF
            curr_ver = (major, minor)
            minimum_os = max(minimum_os or (0, 0), curr_ver)

        elif cmd == _LC_VERSION_MIN_MACOSX:
            if cmdsize < 16:
                fail("MALFORMED")
            version, sdk = struct.unpack_from("<II", data, offset + 8)
            major = (version >> 16) & 0xFFFF
            minor = (version >> 8) & 0xFF
            curr_ver = (major, minor)
            minimum_os = max(minimum_os or (0, 0), curr_ver)

        elif cmd in (_LC_LOAD_DYLIB, _LC_LOAD_WEAK_DYLIB, _LC_REEXPORT_DYLIB):
            if cmdsize < 24:
                fail("MALFORMED")
            str_offset = struct.unpack_from("<I", data, offset + 8)[0]
            if str_offset >= cmdsize:
                fail("MALFORMED")
            raw_str = data[offset + str_offset : offset + cmdsize]
            nul = raw_str.find(b"\x00")
            if nul == -1:
                fail("MALFORMED")
            dylib_name = raw_str[:nul].decode("utf-8", errors="replace")
            needed.append(dylib_name)

        elif cmd in (_LC_RPATH, _LC_RPATH_64):
            if cmdsize < 16:
                fail("MALFORMED")
            str_offset = struct.unpack_from("<I", data, offset + 8)[0]
            if str_offset >= cmdsize:
                fail("MALFORMED")
            raw_str = data[offset + str_offset : offset + cmdsize]
            nul = raw_str.find(b"\x00")
            if nul == -1:
                fail("MALFORMED")
            rpath_str = raw_str[:nul].decode("utf-8", errors="replace")
            rpath.append(rpath_str)

        elif cmd == _LC_SYMTAB:
            if cmdsize < 24:
                fail("MALFORMED")
            symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", data, offset + 8)
            if symoff + nsyms * 16 > len(data) or stroff + strsize > len(data):
                fail("TRUNCATED")
            symtab_cmd = (symoff, nsyms, stroff, strsize)

        elif cmd == _LC_DYSYMTAB:
            if cmdsize < 80:
                fail("MALFORMED")
            fields = struct.unpack_from("<IIIIII", data, offset + 8)
            dysymtab_cmd = fields

        elif cmd in (_LC_DYLD_INFO, _LC_DYLD_INFO_ONLY):
            if cmdsize >= 48:
                export_off, export_size = struct.unpack_from("<II", data, offset + 40)
                if export_off + export_size <= len(data) and export_size > 0:
                    export_trie_range = (export_off, export_size)

        elif cmd == _LC_DYLD_EXPORTS_TRIE:
            if cmdsize >= 16:
                export_off, export_size = struct.unpack_from("<II", data, offset + 8)
                if export_off + export_size <= len(data) and export_size > 0:
                    export_trie_range = (export_off, export_size)

        offset += cmdsize

    if offset != 32 + sizeofcmds:
        fail("MALFORMED")
    if minimum_os is None:
        fail("MISSING_DEPLOYMENT")

    # Determine napi export
    napi = False
    if symtab_cmd is not None:
        symoff, nsyms, stroff, strsize = symtab_cmd
        strtab = data[stroff : stroff + strsize]

        if dysymtab_cmd is not None:
            _, _, iextdefsym, nextdefsym, _, _ = dysymtab_cmd
            if iextdefsym + nextdefsym <= nsyms:
                for i in range(iextdefsym, iextdefsym + nextdefsym):
                    entry_off = symoff + i * 16
                    n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(
                        "<IBBHQ", data, entry_off
                    )
                    if n_strx < len(strtab):
                        nul = strtab.find(b"\x00", n_strx)
                        if nul != -1:
                            sym_name = strtab[n_strx:nul].decode("utf-8", errors="replace")
                            if sym_name in ("_napi_register_module_v1", "napi_register_module_v1"):
                                napi = True
                                break

        if not napi:
            # Full symtab scan for external defined symbols
            for i in range(min(nsyms, _MAX_ENTRIES)):
                entry_off = symoff + i * 16
                n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from(
                    "<IBBHQ", data, entry_off
                )
                if (n_type & 0x01) and n_sect != 0 and n_strx < len(strtab):
                    nul = strtab.find(b"\x00", n_strx)
                    if nul != -1:
                        sym_name = strtab[n_strx:nul].decode("utf-8", errors="replace")
                        if sym_name in ("_napi_register_module_v1", "napi_register_module_v1"):
                            napi = True
                            break

    if not napi and export_trie_range is not None:
        exp_off, exp_sz = export_trie_range
        trie_bytes = data[exp_off : exp_off + exp_sz]
        if b"napi_register_module_v1" in trie_bytes or b"_napi_register_module_v1" in trie_bytes:
            napi = True

    return {
        "format": "macho",
        "architecture": arch,
        "napi": napi,
        "minimum_os": minimum_os,
        "glibc_max": None,
        "needed": needed,
        "rpath": rpath,
        "runpath": [],
        "rpath_runpath": rpath,
        "arch": arch,
    }


def inspect_native(data: bytes) -> dict[str, Any]:
    """Inspect native binary bytes returning architecture, format, and dependency evidence.

    Fails closed on malformed headers, unsupported formats, or unexpected CPU architectures.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        fail("MALFORMED")
    data_bytes = bytes(data)

    if len(data_bytes) < 32:
        fail("TRUNCATED")

    if data_bytes.startswith(b"MZ"):
        fail("UNSUPPORTED_FORMAT")

    if data_bytes.startswith(_ELF_MAGIC):
        return _inspect_elf(data_bytes)

    magic = struct.unpack_from("<I", data_bytes, 0)[0]
    if (
        magic == _MACHO_MAGIC_64_LE
        or magic in _MACHO_FAT_MAGICS
        or magic in (_MACHO_MAGIC_32_LE, _MACHO_MAGIC_32_BE, _MACHO_MAGIC_64_BE)
    ):
        return _inspect_macho(data_bytes)

    fail("MALFORMED")


def _verify_burst_loader(loader_bytes: bytes) -> None:
    """Verify the real Burst loader script permits per-platform prebuild pruning."""
    try:
        text = loader_bytes.decode("utf-8")
    except UnicodeDecodeError:
        fail("LOADER_BLOCKED")

    # Verify structural requirements ensuring selective single-artifact loading
    if "DIRECTORY_SNAPSHOT_BACKEND" not in text:
        fail("LOADER_BLOCKED")
    if "currentDirectorySnapshotArtifact" not in text:
        fail("LOADER_BLOCKED")
    if "loadDirectorySnapshotNative" not in text:
        fail("LOADER_BLOCKED")

    # Verify dynamic path construction targeting only current artifact
    if "${artifact}" not in text and "artifact" not in text:
        fail("LOADER_BLOCKED")

    # Verify absence of unconditional iteration requiring all prebuilds
    if "for (const artifact of" in text or "allArtifacts" in text:
        fail("LOADER_BLOCKED")


def select_native(
    files: Mapping[str, tuple[bytes, int]],
    key: str,
) -> tuple[dict[str, tuple[bytes, int]], str, dict[str, Any]]:
    """Select the target native prebuild, validate Node-API evidence, and prune foreign prebuilds.

    Returns:
        (filtered_files, wheel_platform_tag, transform_dict)
    """
    if not isinstance(files, (dict, Mapping)):
        fail("FILES")
    if key not in SUPPORTED_PREBUILD_KEYS:
        fail("UNSUPPORTED_KEY")

    # Determine archive root prefix
    sample_key = "darwin-arm64"
    sample_rel = EXPECTED_PREBUILD_RELPATHS[sample_key]
    prefix = ""
    if f"package/{sample_rel}" in files:
        prefix = "package/"
    elif sample_rel not in files:
        # Check if missing or different prefix
        fail("MISSING_NATIVE")

    expected_paths: dict[str, str] = {
        k: f"{prefix}{rel}" for k, rel in EXPECTED_PREBUILD_RELPATHS.items()
    }

    # Verify presence of all expected prebuilds
    for k, p in expected_paths.items():
        if p not in files:
            fail("MISSING_NATIVE")

    # Check for unauthorized native files in the entire admitted archive
    expected_path_set = set(expected_paths.values())
    for path, (data_bytes, mode) in files.items():
        if path not in expected_path_set:
            is_native_ext = path.lower().endswith(NATIVE_EXTENSIONS)
            is_native_mag = any(data_bytes.startswith(mag) for mag in NATIVE_MAGIC)
            if is_native_ext or is_native_mag:
                fail("UNEXPECTED_NATIVE")

    # Verify loader permits pruning
    loader_path = f"{prefix}{BURST_LOADER_RELPATH}"
    if loader_path not in files:
        fail("LOADER_BLOCKED")
    _verify_burst_loader(files[loader_path][0])

    # Inspect all four prebuilds
    inspected_prebuilds: dict[str, dict[str, Any]] = {}
    for k, p in expected_paths.items():
        payload_bytes = files[p][0]
        info = inspect_native(payload_bytes)

        # N-API export required for all
        if not info.get("napi"):
            fail("NAPI_REQUIRED")

        # Format and architecture checks
        if k == "darwin-arm64":
            if info["format"] != "macho" or info["architecture"] != "arm64":
                fail("INVALID_ARCH")
            if not info.get("minimum_os"):
                fail("MACHO_DEPLOYMENT")
        elif k == "darwin-x64":
            if info["format"] != "macho" or info["architecture"] != "x86_64":
                fail("INVALID_ARCH")
            if not info.get("minimum_os"):
                fail("MACHO_DEPLOYMENT")
        elif k == "linux-arm64-gnu":
            if info["format"] != "elf" or info["architecture"] != "arm64":
                fail("INVALID_ARCH")
            if not info.get("glibc_max"):
                fail("ELF_GLIBC")
            if info.get("rpath") or info.get("runpath"):
                fail("ELF_RPATH")
            if info.get("needed") != ["libc.so.6"]:
                fail("ELF_NEEDED")
        elif k == "linux-x64-gnu":
            if info["format"] != "elf" or info["architecture"] != "x86_64":
                fail("INVALID_ARCH")
            if not info.get("glibc_max"):
                fail("ELF_GLIBC")
            if info.get("rpath") or info.get("runpath"):
                fail("ELF_RPATH")
            if info.get("needed") != ["libc.so.6"]:
                fail("ELF_NEEDED")

        inspected_prebuilds[k] = info

    # Derive truthful wheel platform tag
    target_info = inspected_prebuilds[key]
    target_path = expected_paths[key]

    if key == "darwin-arm64":
        min_maj, min_min = target_info["minimum_os"]
        wheel_platform_tag = f"macosx_{min_maj}_{min_min}_arm64"
    elif key == "darwin-x64":
        min_maj, min_min = target_info["minimum_os"]
        wheel_platform_tag = f"macosx_{min_maj}_{min_min}_x86_64"
    elif key == "linux-arm64-gnu":
        glibc_minor = target_info["glibc_max"][1]
        wheel_platform_tag = f"manylinux_2_{glibc_minor}_aarch64"
    elif key == "linux-x64-gnu":
        glibc_minor = target_info["glibc_max"][1]
        wheel_platform_tag = f"manylinux_2_{glibc_minor}_x86_64"
    else:
        fail("UNSUPPORTED_KEY")

    if wheel_platform_tag == "any" or wheel_platform_tag.endswith("_any") or "-any" in wheel_platform_tag:
        fail("INVALID_TAG")

    # Prune other 3 .node payloads and record source-bound omitted file rows
    filtered_files = dict(files)
    omissions: list[dict[str, Any]] = []

    for other_key, other_path in sorted(expected_paths.items()):
        if other_key != key:
            omitted_bytes, _ = files[other_path]
            omissions.append({
                "path": other_path,
                "size": len(omitted_bytes),
                "sha256": sha256(omitted_bytes),
            })
            del filtered_files[other_path]

    transform_dict: dict[str, Any] = {
        "target_key": key,
        "wheel_platform_tag": wheel_platform_tag,
        "target_path": target_path,
        "native_facts": {
            "format": target_info["format"],
            "architecture": target_info["architecture"],
            "napi": target_info["napi"],
            "minimum_os": target_info["minimum_os"],
            "glibc_max": target_info["glibc_max"],
            "needed": list(target_info["needed"]),
            "rpath": list(target_info["rpath"]),
            "runpath": list(target_info["runpath"]),
            "size": len(files[target_path][0]),
            "sha256": sha256(files[target_path][0]),
        },
        "omissions": omissions,
    }
    transform_dict["native"] = transform_dict["native_facts"]

    return filtered_files, wheel_platform_tag, transform_dict
