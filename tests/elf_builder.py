"""Synthetic ELF64 little-endian binary builder for testing."""

from __future__ import annotations

import struct
from typing import Any, Sequence

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1

ET_EXEC = 2
ET_DYN = 3

EM_X86_64 = 62
EM_AARCH64 = 183

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

SHT_NULL = 0
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_GNU_verneed = 0x6FFFFFFE


def build_elf(
    *,
    machine: str = "x86_64",
    elf_type: str = "executable",
    interpreter: str | None = None,
    needed: Sequence[str] = (),
    soname: str | None = None,
    rpath: Sequence[str] | str = (),
    runpath: Sequence[str] | str = (),
    version_needs: dict[str, list[str]] | None = None,
    has_dynamic: bool = True,
    # Overrides for adverse and negative testing
    magic: bytes = ELF_MAGIC,
    ei_class: int = ELFCLASS64,
    ei_data: int = ELFDATA2LSB,
    ei_version: int = EV_CURRENT,
    e_version: int = EV_CURRENT,
    e_type_override: int | None = None,
    e_machine_override: int | None = None,
    e_ehsize_override: int | None = None,
    e_phentsize_override: int | None = None,
    e_phnum_override: int | None = None,
    e_shoff_override: int | None = None,
    e_shentsize_override: int | None = None,
    e_shnum_override: int | None = None,
    raw_interpreter: bytes | None = None,
    omit_pt_load: bool = False,
    pt_load_filesz_override: int | None = None,
    pt_load_memsz_override: int | None = None,
    omit_strtab_tag: bool = False,
    omit_strsz_tag: bool = False,
    omit_verneed_tag: bool = False,
    omit_verneednum_tag: bool = False,
    corrupt_strtab_start: bool = False,
    corrupt_strtab_unterminated: bool = False,
    corrupt_strtab_utf8: bool = False,
    corrupt_strtab_size: int | None = None,
    corrupt_strtab_vaddr: int | None = None,
    corrupt_verneed_vaddr: int | None = None,
    corrupt_verneed_num: int | None = None,
    corrupt_verneed_loop: bool = False,
    corrupt_vernaux_loop: bool = False,
    corrupt_verneed_version: int | None = None,
    corrupt_verneed_premature_end: bool = False,
    corrupt_vernaux_premature_end: bool = False,
    corrupt_verneed_empty_filename: bool = False,
    corrupt_vernaux_empty_vername: bool = False,
    corrupt_verneed_missing_aux: bool = False,
    corrupt_dyn_size: int = 0,
    duplicate_interpreter: bool = False,
    duplicate_dynamic: bool = False,
    conflicting_soname: str | None = None,
    include_section_headers: bool = False,
    verneed_in_section_only: bool = False,
    truncate_bytes: int = 0,
    append_bytes: bytes = b"",
) -> bytes:
    """Construct synthetic ELF64 binary with exact headers and tables."""
    # Machine architecture code
    if e_machine_override is not None:
        e_machine = e_machine_override
    elif machine == "x86_64":
        e_machine = EM_X86_64
    elif machine == "aarch64":
        e_machine = EM_AARCH64
    else:
        raise ValueError(f"Unknown machine: {machine}")

    # ELF object type code
    if e_type_override is not None:
        e_type = e_type_override
    elif elf_type == "executable":
        e_type = ET_EXEC
    elif elf_type == "shared":
        e_type = ET_DYN
    else:
        raise ValueError(f"Unknown elf_type: {elf_type}")

    base_vaddr = 0x400000 if e_type == ET_EXEC else 0x10000

    # Interpreter payload
    interp_payload: bytes | None = None
    if raw_interpreter is not None:
        interp_payload = raw_interpreter
    elif interpreter is not None:
        interp_payload = interpreter.encode("utf-8") + b"\x00"

    # Build String Table (.dynstr)
    strtab = bytearray(b"\x00")  # Offset 0 is empty string
    needed_offsets: list[int] = []
    for lib in needed:
        needed_offsets.append(len(strtab))
        strtab.extend(lib.encode("utf-8") + b"\x00")

    soname_offset: int | None = None
    if soname is not None:
        soname_offset = len(strtab)
        strtab.extend(soname.encode("utf-8") + b"\x00")

    conflicting_soname_offset: int | None = None
    if conflicting_soname is not None:
        conflicting_soname_offset = len(strtab)
        strtab.extend(conflicting_soname.encode("utf-8") + b"\x00")

    rpath_offset: int | None = None
    if rpath:
        rpath_str = ":".join(rpath) if isinstance(rpath, (list, tuple)) else str(rpath)
        rpath_offset = len(strtab)
        strtab.extend(rpath_str.encode("utf-8") + b"\x00")

    runpath_offset: int | None = None
    if runpath:
        runpath_str = ":".join(runpath) if isinstance(runpath, (list, tuple)) else str(runpath)
        runpath_offset = len(strtab)
        strtab.extend(runpath_str.encode("utf-8") + b"\x00")

    verneed_file_offsets: dict[str, int] = {}
    vernaux_name_offsets: dict[str, int] = {}
    if version_needs:
        for filename, versions in version_needs.items():
            if filename not in verneed_file_offsets:
                if corrupt_verneed_empty_filename:
                    verneed_file_offsets[filename] = 0
                else:
                    verneed_file_offsets[filename] = len(strtab)
                    strtab.extend(filename.encode("utf-8") + b"\x00")
            for ver in versions:
                if ver not in vernaux_name_offsets:
                    if corrupt_vernaux_empty_vername:
                        vernaux_name_offsets[ver] = 0
                    else:
                        vernaux_name_offsets[ver] = len(strtab)
                        strtab.extend(ver.encode("utf-8") + b"\x00")

    if corrupt_strtab_start:
        strtab[0] = ord(b"X")
    if corrupt_strtab_unterminated:
        strtab = bytearray(b"\x00" + b"A" * (len(strtab) - 1))
    if corrupt_strtab_utf8:
        strtab.extend(b"\xff\xfe\x00")

    strtab_bytes = bytes(strtab)

    # Calculate program header count to estimate offsets
    num_phdrs = 0
    if not omit_pt_load:
        num_phdrs += 1
    if interp_payload is not None:
        num_phdrs += 1
        if duplicate_interpreter:
            num_phdrs += 1
    if has_dynamic:
        num_phdrs += 1
        if duplicate_dynamic:
            num_phdrs += 1

    e_phentsize = 56 if e_phentsize_override is None else e_phentsize_override
    e_phnum = num_phdrs if e_phnum_override is None else e_phnum_override
    e_ehsize = 64 if e_ehsize_override is None else e_ehsize_override

    e_phoff = 64
    current_offset = e_phoff + e_phnum * e_phentsize
    # Align to 8 bytes
    current_offset = (current_offset + 7) & ~7

    # Layout interpreter
    interp_offset: int | None = None
    if interp_payload is not None:
        interp_offset = current_offset
        current_offset += len(interp_payload)
        current_offset = (current_offset + 7) & ~7

    # Layout string table (.dynstr)
    strtab_offset = current_offset
    strtab_size = len(strtab_bytes)
    strtab_vaddr = base_vaddr + strtab_offset
    if corrupt_strtab_vaddr is not None:
        strtab_vaddr = corrupt_strtab_vaddr
    if corrupt_strtab_size is not None:
        strtab_size = corrupt_strtab_size
    current_offset += len(strtab_bytes)
    current_offset = (current_offset + 7) & ~7

    # Build and layout Version Needs (.gnu.version_r)
    verneed_bytes = bytearray()
    verneed_num_val = 0
    verneed_offset: int | None = None
    verneed_vaddr: int | None = None

    if version_needs:
        verneed_offset = current_offset
        items = list(version_needs.items())
        verneed_num_val = len(items) if corrupt_verneed_num is None else corrupt_verneed_num
        if corrupt_verneed_loop:
            verneed_num_val = len(items) + 1

        for i, (filename, versions) in enumerate(items):
            vn_entry_start = len(verneed_bytes)
            vn_version = 1 if corrupt_verneed_version is None else corrupt_verneed_version
            vn_cnt = len(versions) if not corrupt_vernaux_loop else len(versions) + 1
            vn_file = verneed_file_offsets[filename]
            vn_aux = 16 if not corrupt_verneed_missing_aux else 0

            is_last_vn = i == len(items) - 1
            if is_last_vn:
                vn_next = 0
                if corrupt_verneed_loop:
                    # Point back to entry 0
                    vn_next = (-(vn_entry_start)) & 0xFFFFFFFF
            else:
                if corrupt_verneed_premature_end:
                    vn_next = 0
                else:
                    vn_next = 16 + len(versions) * 16

            verneed_bytes.extend(
                struct.pack("<HHIII", vn_version, vn_cnt, vn_file, vn_aux, vn_next)
            )

            for j, ver in enumerate(versions):
                vna_entry_start = len(verneed_bytes)
                vna_hash = 0
                vna_flags = 0
                vna_other = j + 2
                vna_name = vernaux_name_offsets[ver]

                is_last_vna = j == len(versions) - 1
                if is_last_vna:
                    vna_next = 0
                    if corrupt_vernaux_loop:
                        vna_next = (-(vna_entry_start - (vn_entry_start + 16))) & 0xFFFFFFFF
                else:
                    if corrupt_vernaux_premature_end:
                        vna_next = 0
                    else:
                        vna_next = 16

                verneed_bytes.extend(
                    struct.pack("<IHHII", vna_hash, vna_flags, vna_other, vna_name, vna_next)
                )

        current_offset += len(verneed_bytes)
        current_offset = (current_offset + 7) & ~7
        verneed_vaddr = base_vaddr + verneed_offset
        if corrupt_verneed_vaddr is not None:
            verneed_vaddr = corrupt_verneed_vaddr

    # Build Dynamic section
    dyn_bytes = bytearray()
    dyn_offset: int | None = None
    dyn_vaddr: int | None = None

    if has_dynamic:
        dyn_entries: list[tuple[int, int]] = []
        for off in needed_offsets:
            dyn_entries.append((DT_NEEDED, off))
        if soname_offset is not None:
            dyn_entries.append((DT_SONAME, soname_offset))
        if conflicting_soname_offset is not None:
            dyn_entries.append((DT_SONAME, conflicting_soname_offset))
        if rpath_offset is not None:
            dyn_entries.append((DT_RPATH, rpath_offset))
        if runpath_offset is not None:
            dyn_entries.append((DT_RUNPATH, runpath_offset))

        if not omit_strtab_tag:
            dyn_entries.append((DT_STRTAB, strtab_vaddr))
        if not omit_strsz_tag:
            dyn_entries.append((DT_STRSZ, strtab_size))

        if version_needs and not verneed_in_section_only:
            if not omit_verneed_tag and verneed_vaddr is not None:
                dyn_entries.append((DT_VERNEED, verneed_vaddr))
            if not omit_verneednum_tag:
                dyn_entries.append((DT_VERNEEDNUM, verneed_num_val))

        dyn_entries.append((DT_NULL, 0))

        for tag, val in dyn_entries:
            dyn_bytes.extend(struct.pack("<qQ", tag, val))

        if corrupt_dyn_size > 0:
            dyn_bytes.extend(b"\x00" * corrupt_dyn_size)

        dyn_offset = current_offset
        dyn_vaddr = base_vaddr + dyn_offset
        current_offset += len(dyn_bytes)
        current_offset = (current_offset + 7) & ~7

    loadable_size = current_offset

    # Optional section headers
    sh_bytes = bytearray()
    e_shoff = 0
    e_shnum = 0
    e_shentsize = 64 if e_shentsize_override is None else e_shentsize_override
    e_shstrndx = 0

    if include_section_headers or verneed_in_section_only:
        e_shoff = current_offset
        # Section 0: SHT_NULL
        sh_bytes.extend(struct.pack("<IIQQQQIIQQ", 0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0))
        # Section 1: .dynstr
        sh_bytes.extend(
            struct.pack(
                "<IIQQQQIIQQ",
                0,
                SHT_STRTAB,
                2,  # SHF_ALLOC
                strtab_vaddr,
                strtab_offset,
                len(strtab_bytes),
                0,
                0,
                1,
                0,
            )
        )
        e_shnum = 2
        if version_needs:
            # Section 2: .gnu.version_r
            sh_bytes.extend(
                struct.pack(
                    "<IIQQQQIIQQ",
                    0,
                    SHT_GNU_verneed,
                    2,  # SHF_ALLOC
                    verneed_vaddr if verneed_vaddr is not None else 0,
                    verneed_offset if verneed_offset is not None else 0,
                    len(verneed_bytes),
                    1,  # sh_link -> section 1 (.dynstr)
                    verneed_num_val,  # sh_info -> verneed count
                    4,
                    16,
                )
            )
            e_shnum = 3

    if e_shoff_override is not None:
        e_shoff = e_shoff_override
    if e_shnum_override is not None:
        e_shnum = e_shnum_override

    # Build Program Headers
    ph_bytes = bytearray()
    if not omit_pt_load:
        p_filesz = loadable_size if pt_load_filesz_override is None else pt_load_filesz_override
        p_memsz = loadable_size if pt_load_memsz_override is None else pt_load_memsz_override
        ph_bytes.extend(
            struct.pack(
                "<IIQQQQQQ",
                PT_LOAD,
                7,  # PF_R | PF_W | PF_X
                0,  # p_offset
                base_vaddr,  # p_vaddr
                base_vaddr,  # p_paddr
                p_filesz,
                p_memsz,
                0x1000,  # align
            )
        )

    if interp_payload is not None and interp_offset is not None:
        interp_phdr = struct.pack(
            "<IIQQQQQQ",
            PT_INTERP,
            4,  # PF_R
            interp_offset,
            base_vaddr + interp_offset,
            base_vaddr + interp_offset,
            len(interp_payload),
            len(interp_payload),
            1,
        )
        ph_bytes.extend(interp_phdr)
        if duplicate_interpreter:
            ph_bytes.extend(interp_phdr)

    if has_dynamic and dyn_offset is not None and dyn_vaddr is not None:
        dyn_phdr = struct.pack(
            "<IIQQQQQQ",
            PT_DYNAMIC,
            6,  # PF_R | PF_W
            dyn_offset,
            dyn_vaddr,
            dyn_vaddr,
            len(dyn_bytes),
            len(dyn_bytes),
            8,
        )
        ph_bytes.extend(dyn_phdr)
        if duplicate_dynamic:
            ph_bytes.extend(dyn_phdr)

    # Build ELF Identification (16 bytes)
    e_ident = bytearray(16)
    e_ident[: len(magic)] = magic
    e_ident[4] = ei_class
    e_ident[5] = ei_data
    e_ident[6] = ei_version

    # Build ELF64 Header (64 bytes)
    ehdr_bytes = struct.pack(
        "<16sHHIQQQIHHHHHH",
        bytes(e_ident),
        e_type,
        e_machine,
        e_version,
        base_vaddr + 0x100,  # e_entry
        e_phoff,
        e_shoff,
        0,  # e_flags
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    )

    # Assemble full file image
    out = bytearray(ehdr_bytes)
    # Pad to e_phoff
    if len(out) < e_phoff:
        out.extend(b"\x00" * (e_phoff - len(out)))
    out.extend(ph_bytes)

    if interp_payload is not None and interp_offset is not None:
        if len(out) < interp_offset:
            out.extend(b"\x00" * (interp_offset - len(out)))
        out.extend(interp_payload)

    if len(out) < strtab_offset:
        out.extend(b"\x00" * (strtab_offset - len(out)))
    out.extend(strtab_bytes)

    if version_needs and verneed_offset is not None:
        if len(out) < verneed_offset:
            out.extend(b"\x00" * (verneed_offset - len(out)))
        out.extend(verneed_bytes)

    if has_dynamic and dyn_offset is not None:
        if len(out) < dyn_offset:
            out.extend(b"\x00" * (dyn_offset - len(out)))
        out.extend(dyn_bytes)

    if len(out) < loadable_size:
        out.extend(b"\x00" * (loadable_size - len(out)))

    if sh_bytes:
        if len(out) < e_shoff:
            out.extend(b"\x00" * (e_shoff - len(out)))
        out.extend(sh_bytes)

    if truncate_bytes > 0:
        out = out[:-truncate_bytes]

    if append_bytes:
        out.extend(append_bytes)

    return bytes(out)
