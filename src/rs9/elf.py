"""ELF64 little-endian binary evidence extraction and validation."""

from __future__ import annotations

import struct
from typing import Any, Callable, NamedTuple

from rs9.errors import ContractError

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1

ET_EXEC = 2
ET_DYN = 3

EM_X86_64 = 62
EM_AARCH64 = 183

ELF64_EHDR_SIZE = 64
ELF64_PHDR_SIZE = 56
ELF64_SHDR_SIZE = 64
ELF64_DYN_SIZE = 16
ELF64_VERNEED_SIZE = 16
ELF64_VERNAUX_SIZE = 16

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3

DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29
DT_VERNEED = 0x6FFFFFFE
DT_VERNEEDNUM = 0x6FFFFFFF

SHT_STRTAB = 3
SHT_GNU_verneed = 0x6FFFFFFE

MAX_PHNUM = 10_000
MAX_SHNUM = 10_000
MAX_DYN_ENTRIES = 10_000
MAX_VERNEED_ENTRIES = 10_000
MAX_VERNAUX_ENTRIES = 10_000
MAX_INTERP_SIZE = 4096

ELF64_EHDR_FMT = "<16sHHIQQQIHHHHHH"
ELF64_PHDR_FMT = "<IIQQQQQQ"
ELF64_SHDR_FMT = "<IIQQQQIIQQ"
ELF64_DYN_FMT = "<qQ"
ELF64_VERNEED_FMT = "<HHIII"
ELF64_VERNAUX_FMT = "<IHHII"


class _LoadSegment(NamedTuple):
    p_vaddr: int
    p_memsz: int
    p_offset: int
    p_filesz: int


def _parse_verneed_entries(
    data: bytes,
    start_offset: int,
    count: int,
    get_str: Callable[[int], str],
) -> dict[str, list[str]]:
    """Parse GNU version need entries with loop, table, and file bounds."""
    if count == 0:
        return {}
    if count < 0 or count > MAX_VERNEED_ENTRIES:
        raise ContractError("MALFORMED_ELF", "Invalid version need entry count")

    version_needs: dict[str, list[str]] = {}
    current_off = start_offset
    visited_verneed: set[int] = set()

    for i in range(count):
        if current_off < 0 or current_off + ELF64_VERNEED_SIZE > len(data):
            raise ContractError("TRUNCATED_ELF", "Version need entry extends beyond file bounds")
        if current_off in visited_verneed:
            raise ContractError("MALFORMED_ELF", "Cycle detected in version need table")
        visited_verneed.add(current_off)

        vn_version, vn_cnt, vn_file, vn_aux, vn_next = struct.unpack_from(
            ELF64_VERNEED_FMT, data, current_off
        )
        if vn_version != 1:
            raise ContractError("MALFORMED_ELF", "Unsupported version need record version")
        if vn_cnt < 0 or vn_cnt > MAX_VERNAUX_ENTRIES:
            raise ContractError("MALFORMED_ELF", "Invalid version aux entry count")

        filename = get_str(vn_file)
        if not filename:
            raise ContractError("MALFORMED_ELF", "Empty filename in version need entry")

        aux_names: list[str] = []
        if vn_cnt > 0:
            if vn_aux == 0:
                raise ContractError("MALFORMED_ELF", "Missing version aux offset")
            aux_off = current_off + vn_aux
            visited_aux: set[int] = set()

            for j in range(vn_cnt):
                if aux_off < 0 or aux_off + ELF64_VERNAUX_SIZE > len(data):
                    raise ContractError("TRUNCATED_ELF", "Version aux entry extends beyond file bounds")
                if aux_off in visited_aux:
                    raise ContractError("MALFORMED_ELF", "Cycle detected in version aux table")
                visited_aux.add(aux_off)

                vna_hash, vna_flags, vna_other, vna_name, vna_next = struct.unpack_from(
                    ELF64_VERNAUX_FMT, data, aux_off
                )
                ver_name = get_str(vna_name)
                if not ver_name:
                    raise ContractError("MALFORMED_ELF", "Empty version name in version aux entry")
                aux_names.append(ver_name)

                if j < vn_cnt - 1:
                    if vna_next == 0:
                        raise ContractError("TRUNCATED_ELF", "Premature termination of version aux list")
                    vna_delta = vna_next if vna_next < 0x80000000 else vna_next - 0x100000000
                    aux_off += vna_delta

        version_needs.setdefault(filename, []).extend(aux_names)

        if i < count - 1:
            if vn_next == 0:
                raise ContractError("TRUNCATED_ELF", "Premature termination of version need list")
            vn_delta = vn_next if vn_next < 0x80000000 else vn_next - 0x100000000
            current_off += vn_delta

    return version_needs


def parse_elf(data: bytes) -> dict[str, Any]:
    """Parse ELF64 little-endian binary data and extract evidence.

    Returns a dictionary matching:
        {
            'machine': 'x86_64' | 'aarch64',
            'type': 'executable' | 'shared',
            'interpreter': str | None,
            'needed': list[str],
            'soname': str | None,
            'rpath': list[str],
            'runpath': list[str],
            'version_needs': dict[str, list[str]],
        }
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ContractError("INVALID_TYPE", "ELF data must be bytes-like")
    data = bytes(data)

    if len(data) < ELF64_EHDR_SIZE:
        raise ContractError("TRUNCATED_ELF", "Data too short for ELF64 header")

    if data[:4] != ELF_MAGIC:
        raise ContractError("MALFORMED_ELF", "Invalid ELF magic bytes")

    ei_class = data[4]
    if ei_class == 1:
        raise ContractError("UNSUPPORTED_ELF", "ELF32 is not supported")
    if ei_class != ELFCLASS64:
        raise ContractError("UNSUPPORTED_ELF", "Unsupported ELF class")

    ei_data = data[5]
    if ei_data == 2:
        raise ContractError("UNSUPPORTED_ELF", "Big-endian ELF is not supported")
    if ei_data != ELFDATA2LSB:
        raise ContractError("UNSUPPORTED_ELF", "Unsupported ELF data encoding")

    ei_version = data[6]
    if ei_version != EV_CURRENT:
        raise ContractError("MALFORMED_ELF", "Invalid ELF identification version")

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
    ) = struct.unpack_from(ELF64_EHDR_FMT, data, 0)

    if e_version != EV_CURRENT:
        raise ContractError("MALFORMED_ELF", "Invalid ELF header version")

    if e_ehsize < ELF64_EHDR_SIZE:
        raise ContractError("MALFORMED_ELF", "Invalid ELF header size")

    if e_type == ET_EXEC:
        obj_type = "executable"
    elif e_type == ET_DYN:
        obj_type = "shared"
    else:
        raise ContractError("UNSUPPORTED_ELF", "Unsupported ELF file type")

    if e_machine == EM_X86_64:
        machine_arch = "x86_64"
    elif e_machine == EM_AARCH64:
        machine_arch = "aarch64"
    else:
        raise ContractError("UNSUPPORTED_ELF", "Unsupported machine architecture")

    if e_phnum > MAX_PHNUM:
        raise ContractError("MALFORMED_ELF", "Program header count exceeds limit")

    if e_phnum > 0 and e_phentsize < ELF64_PHDR_SIZE:
        raise ContractError("MALFORMED_ELF", "Invalid program header entry size")

    ph_table_end = e_phoff + e_phnum * e_phentsize
    if ph_table_end > len(data):
        raise ContractError("TRUNCATED_ELF", "Program header table extends beyond file bounds")

    load_segments: list[_LoadSegment] = []
    interp_segment: tuple[int, int] | None = None
    dynamic_segment: tuple[int, int] | None = None

    for i in range(e_phnum):
        phdr_offset = e_phoff + i * e_phentsize
        (
            p_type,
            p_flags,
            p_offset,
            p_vaddr,
            p_paddr,
            p_filesz,
            p_memsz,
            p_align,
        ) = struct.unpack_from(ELF64_PHDR_FMT, data, phdr_offset)

        if p_type == PT_LOAD:
            if p_filesz > p_memsz:
                raise ContractError("MALFORMED_ELF", "Segment file size exceeds memory size")
            load_segments.append(
                _LoadSegment(
                    p_vaddr=p_vaddr,
                    p_memsz=p_memsz,
                    p_offset=p_offset,
                    p_filesz=p_filesz,
                )
            )

        if p_filesz > 0 and p_offset + p_filesz > len(data):
            raise ContractError("TRUNCATED_ELF", "Segment data extends beyond file bounds")
        elif p_type == PT_INTERP:
            if interp_segment is not None:
                raise ContractError("MALFORMED_ELF", "Multiple PT_INTERP segments detected")
            interp_segment = (p_offset, p_filesz)
        elif p_type == PT_DYNAMIC:
            if dynamic_segment is not None:
                raise ContractError("MALFORMED_ELF", "Multiple PT_DYNAMIC segments detected")
            dynamic_segment = (p_offset, p_filesz)

    interpreter: str | None = None
    if interp_segment is not None:
        p_offset, p_filesz = interp_segment
        if p_filesz <= 0 or p_filesz > MAX_INTERP_SIZE:
            raise ContractError("INVALID_INTERPRETER", "Invalid PT_INTERP segment size")
        interp_raw = data[p_offset : p_offset + p_filesz]
        null_idx = interp_raw.find(b"\x00")
        if null_idx == -1:
            raise ContractError("INVALID_INTERPRETER", "Interpreter is not null-terminated")
        if null_idx == 0:
            raise ContractError("INVALID_INTERPRETER", "Interpreter path is empty")
        if any(interp_raw[null_idx + 1:]):
            raise ContractError("INVALID_INTERPRETER", "Interpreter contains nonzero trailing bytes")
        interp_bytes = interp_raw[:null_idx]
        try:
            interp_str = interp_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise ContractError("INVALID_INTERPRETER", "Interpreter is not valid UTF-8")
        if not interp_str.startswith("/"):
            raise ContractError("INVALID_INTERPRETER", "Interpreter path must be absolute")
        if any(ord(c) < 32 or ord(c) == 127 for c in interp_str):
            raise ContractError("INVALID_INTERPRETER", "Interpreter path contains control characters")
        interpreter = interp_str

    def vaddr_to_offset(vaddr: int, size: int = 1) -> int:
        matches = [seg.p_offset + (vaddr - seg.p_vaddr) for seg in load_segments
                   if seg.p_vaddr <= vaddr and vaddr + size <= seg.p_vaddr + seg.p_filesz]
        if len(set(matches)) == 1:
            return matches[0]
        raise ContractError("MALFORMED_ELF", "Virtual address not mapped by any PT_LOAD segment")

    # Check section headers bounds if present
    if e_shoff != 0 and e_shnum > 0:
        if e_shentsize < ELF64_SHDR_SIZE:
            raise ContractError("MALFORMED_ELF", "Invalid section header entry size")
        if e_shnum > MAX_SHNUM:
            raise ContractError("MALFORMED_ELF", "Section header count exceeds limit")
        sh_table_end = e_shoff + e_shnum * e_shentsize
        if sh_table_end > len(data):
            raise ContractError("TRUNCATED_ELF", "Section header table extends beyond file bounds")

    needed: list[str] = []
    soname: str | None = None
    rpath: list[str] = []
    runpath: list[str] = []
    version_needs: dict[str, list[str]] = {}

    strtab_vaddr: int | None = None
    strtab_sz: int | None = None
    verneed_vaddr: int | None = None
    verneed_num: int | None = None

    if dynamic_segment is not None:
        dyn_offset, dyn_filesz = dynamic_segment
        if dyn_filesz % ELF64_DYN_SIZE != 0:
            raise ContractError("MALFORMED_ELF", "PT_DYNAMIC segment size is not a multiple of 16")
        num_dyn = dyn_filesz // ELF64_DYN_SIZE
        if num_dyn > MAX_DYN_ENTRIES:
            raise ContractError("MALFORMED_ELF", "PT_DYNAMIC entries exceed limit")

        needed_offsets: list[int] = []
        rpath_offsets: list[int] = []
        runpath_offsets: list[int] = []
        soname_offset: int | None = None

        for i in range(num_dyn):
            entry_off = dyn_offset + i * ELF64_DYN_SIZE
            d_tag, d_val = struct.unpack_from(ELF64_DYN_FMT, data, entry_off)
            if d_tag == DT_NULL:
                break
            elif d_tag == DT_NEEDED:
                needed_offsets.append(d_val)
            elif d_tag == DT_SONAME:
                if soname_offset is not None and soname_offset != d_val:
                    raise ContractError("MALFORMED_ELF", "Conflicting DT_SONAME entries")
                soname_offset = d_val
            elif d_tag == DT_RPATH:
                rpath_offsets.append(d_val)
            elif d_tag == DT_RUNPATH:
                runpath_offsets.append(d_val)
            elif d_tag == DT_STRTAB:
                if strtab_vaddr is not None and strtab_vaddr != d_val:
                    raise ContractError("MALFORMED_ELF", "Conflicting DT_STRTAB entries")
                strtab_vaddr = d_val
            elif d_tag == DT_STRSZ:
                if strtab_sz is not None and strtab_sz != d_val:
                    raise ContractError("MALFORMED_ELF", "Conflicting DT_STRSZ entries")
                strtab_sz = d_val
            elif d_tag == DT_VERNEED:
                if verneed_vaddr is not None and verneed_vaddr != d_val:
                    raise ContractError("MALFORMED_ELF", "Conflicting DT_VERNEED entries")
                verneed_vaddr = d_val
            elif d_tag == DT_VERNEEDNUM:
                if verneed_num is not None and verneed_num != d_val:
                    raise ContractError("MALFORMED_ELF", "Conflicting DT_VERNEEDNUM entries")
                verneed_num = d_val
        else:
            raise ContractError("MALFORMED_ELF", "Dynamic table lacks DT_NULL terminator")

        strtab_data: bytes | None = None
        if strtab_vaddr is not None or strtab_sz is not None:
            if strtab_vaddr is None or strtab_sz is None:
                raise ContractError("MALFORMED_ELF", "DT_STRTAB and DT_STRSZ must both be present")
            if strtab_sz < 1 or strtab_sz > len(data):
                raise ContractError("INVALID_STRING_TABLE", "Invalid dynamic string table size")
            strtab_off = vaddr_to_offset(strtab_vaddr, strtab_sz)
            if strtab_off + strtab_sz > len(data):
                raise ContractError("TRUNCATED_ELF", "Dynamic string table extends beyond file bounds")
            strtab_data = data[strtab_off : strtab_off + strtab_sz]
            if strtab_data[0] != 0:
                raise ContractError("INVALID_STRING_TABLE", "Dynamic string table must start with null byte")
        elif (
            needed_offsets
            or soname_offset is not None
            or rpath_offsets
            or runpath_offsets
            or verneed_vaddr is not None
        ):
            raise ContractError("MALFORMED_ELF", "Missing dynamic string table")

        def get_str(off: int) -> str:
            if strtab_data is None:
                raise ContractError("MALFORMED_ELF", "String table unavailable")
            if off < 0 or off >= len(strtab_data):
                raise ContractError("MALFORMED_ELF", "String table offset out of bounds")
            null_pos = strtab_data.find(b"\x00", off)
            if null_pos == -1:
                raise ContractError("MALFORMED_ELF", "Unterminated string in string table")
            raw = strtab_data[off:null_pos]
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                raise ContractError("INVALID_STRING_TABLE", "String table contains invalid UTF-8")

        for off in needed_offsets:
            s = get_str(off)
            if not s:
                raise ContractError("MALFORMED_ELF", "Empty DT_NEEDED entry")
            needed.append(s)

        if soname_offset is not None:
            s = get_str(soname_offset)
            soname = s if s else None

        for off in rpath_offsets:
            s = get_str(off)
            for part in s.split(":"):
                if part:
                    rpath.append(part)

        for off in runpath_offsets:
            s = get_str(off)
            for part in s.split(":"):
                if part:
                    runpath.append(part)

        if verneed_vaddr is not None or verneed_num is not None:
            if verneed_vaddr is None or verneed_num is None:
                raise ContractError("MALFORMED_ELF", "DT_VERNEED and DT_VERNEEDNUM must both be present")
            if verneed_num < 0 or verneed_num > MAX_VERNEED_ENTRIES:
                raise ContractError("MALFORMED_ELF", "Invalid DT_VERNEEDNUM count")

            verneed_off = vaddr_to_offset(verneed_vaddr)
            bound = min(seg.p_offset + seg.p_filesz for seg in load_segments
                        if seg.p_vaddr <= verneed_vaddr < seg.p_vaddr + seg.p_filesz)
            version_needs = _parse_verneed_entries(data[:bound], verneed_off, verneed_num, get_str)

    # Section fallback for version needs if not provided via dynamic tags
    if not version_needs and verneed_vaddr is None and e_shoff != 0 and e_shnum > 0:
        for i in range(e_shnum):
            sh_entry_off = e_shoff + i * e_shentsize
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
            ) = struct.unpack_from(ELF64_SHDR_FMT, data, sh_entry_off)

            if sh_type == SHT_GNU_verneed:
                if sh_link >= e_shnum:
                    raise ContractError("MALFORMED_ELF", "Invalid string table link in verneed section")
                str_sh_off = e_shoff + sh_link * e_shentsize
                (
                    _,
                    s_type,
                    _,
                    _,
                    s_offset,
                    s_size,
                    _,
                    _,
                    _,
                    _,
                ) = struct.unpack_from(ELF64_SHDR_FMT, data, str_sh_off)
                if s_type != SHT_STRTAB:
                    raise ContractError("MALFORMED_ELF", "Verneed linked section is not a string table")
                if s_offset + s_size > len(data):
                    raise ContractError("TRUNCATED_ELF", "Linked string table section extends beyond file bounds")
                sec_strtab = data[s_offset : s_offset + s_size]
                if len(sec_strtab) == 0 or sec_strtab[0] != 0:
                    raise ContractError("INVALID_STRING_TABLE", "Section string table must start with null byte")

                def sec_get_str(off: int) -> str:
                    if off < 0 or off >= len(sec_strtab):
                        raise ContractError("MALFORMED_ELF", "String table offset out of bounds")
                    null_pos = sec_strtab.find(b"\x00", off)
                    if null_pos == -1:
                        raise ContractError("MALFORMED_ELF", "Unterminated string in string table")
                    try:
                        return sec_strtab[off:null_pos].decode("utf-8")
                    except UnicodeDecodeError:
                        raise ContractError("INVALID_STRING_TABLE", "String table contains invalid UTF-8")

                if sh_offset + sh_size > len(data):
                    raise ContractError("TRUNCATED_ELF", "Verneed section extends beyond file bounds")
                version_needs = _parse_verneed_entries(data[:sh_offset + sh_size], sh_offset, sh_info, sec_get_str)
                break

    return {
        "machine": machine_arch,
        "type": obj_type,
        "interpreter": interpreter,
        "needed": needed,
        "soname": soname,
        "rpath": rpath,
        "runpath": runpath,
        "version_needs": version_needs,
    }
