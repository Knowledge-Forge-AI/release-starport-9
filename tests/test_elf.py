"""Tests for ELF64 evidence extraction and validation."""

from __future__ import annotations

import unittest

from rs9.elf import parse_elf
from rs9.errors import ContractError
from tests.elf_builder import build_elf


class ElfParserTests(unittest.TestCase):
    def test_positive_x86_64_executable_with_version_needs(self):
        elf_bytes = build_elf(
            machine="x86_64",
            elf_type="executable",
            interpreter="/lib64/ld-linux-x86-64.so.2",
            needed=["libc.so.6", "libpthread.so.0"],
            rpath=["/opt/custom/lib", "/usr/local/lib"],
            runpath=["$ORIGIN/../lib"],
            version_needs={
                "libc.so.6": ["GLIBC_2.2.5", "GLIBC_2.14"],
                "libpthread.so.0": ["GLIBC_2.2.5"],
            },
        )
        result = parse_elf(elf_bytes)
        self.assertEqual(
            result,
            {
                "machine": "x86_64",
                "type": "executable",
                "interpreter": "/lib64/ld-linux-x86-64.so.2",
                "needed": ["libc.so.6", "libpthread.so.0"],
                "soname": None,
                "rpath": ["/opt/custom/lib", "/usr/local/lib"],
                "runpath": ["$ORIGIN/../lib"],
                "version_needs": {
                    "libc.so.6": ["GLIBC_2.2.5", "GLIBC_2.14"],
                    "libpthread.so.0": ["GLIBC_2.2.5"],
                },
            },
        )

    def test_positive_aarch64_executable_with_version_needs(self):
        elf_bytes = build_elf(
            machine="aarch64",
            elf_type="executable",
            interpreter="/lib/ld-linux-aarch64.so.1",
            needed=["libc.so.6", "libm.so.6"],
            runpath=["$ORIGIN/../lib64"],
            version_needs={
                "libc.so.6": ["GLIBC_2.17", "GLIBC_2.28"],
                "libm.so.6": ["GLIBC_2.17"],
            },
        )
        result = parse_elf(elf_bytes)
        self.assertEqual(
            result,
            {
                "machine": "aarch64",
                "type": "executable",
                "interpreter": "/lib/ld-linux-aarch64.so.1",
                "needed": ["libc.so.6", "libm.so.6"],
                "soname": None,
                "rpath": [],
                "runpath": ["$ORIGIN/../lib64"],
                "version_needs": {
                    "libc.so.6": ["GLIBC_2.17", "GLIBC_2.28"],
                    "libm.so.6": ["GLIBC_2.17"],
                },
            },
        )

    def test_positive_x86_64_shared_library_with_soname(self):
        elf_bytes = build_elf(
            machine="x86_64",
            elf_type="shared",
            soname="libexample.so.1",
            needed=["libutils.so.2"],
            version_needs={"libutils.so.2": ["LIBUTILS_1.0"]},
        )
        result = parse_elf(elf_bytes)
        self.assertEqual(
            result,
            {
                "machine": "x86_64",
                "type": "shared",
                "interpreter": None,
                "needed": ["libutils.so.2"],
                "soname": "libexample.so.1",
                "rpath": [],
                "runpath": [],
                "version_needs": {"libutils.so.2": ["LIBUTILS_1.0"]},
            },
        )

    def test_positive_aarch64_shared_library_with_soname(self):
        elf_bytes = build_elf(
            machine="aarch64",
            elf_type="shared",
            soname="libcore.so.2",
            needed=["libc.so.6"],
            version_needs={"libc.so.6": ["GLIBC_2.17"]},
        )
        result = parse_elf(elf_bytes)
        self.assertEqual(
            result,
            {
                "machine": "aarch64",
                "type": "shared",
                "interpreter": None,
                "needed": ["libc.so.6"],
                "soname": "libcore.so.2",
                "rpath": [],
                "runpath": [],
                "version_needs": {"libc.so.6": ["GLIBC_2.17"]},
            },
        )

    def test_positive_static_executable(self):
        elf_bytes = build_elf(
            machine="x86_64",
            elf_type="executable",
            has_dynamic=False,
            interpreter=None,
        )
        result = parse_elf(elf_bytes)
        self.assertEqual(
            result,
            {
                "machine": "x86_64",
                "type": "executable",
                "interpreter": None,
                "needed": [],
                "soname": None,
                "rpath": [],
                "runpath": [],
                "version_needs": {},
            },
        )

    def test_positive_version_needs_section_fallback(self):
        elf_bytes = build_elf(
            machine="x86_64",
            elf_type="shared",
            needed=["libc.so.6"],
            version_needs={"libc.so.6": ["GLIBC_2.17"]},
            verneed_in_section_only=True,
        )
        result = parse_elf(elf_bytes)
        self.assertEqual(
            result["version_needs"],
            {"libc.so.6": ["GLIBC_2.17"]},
        )

    def test_positive_rpath_runpath_colon_separated(self):
        elf_bytes = build_elf(
            machine="x86_64",
            rpath="/lib1:/lib2::/lib3",
            runpath="/run1:/run2",
        )
        result = parse_elf(elf_bytes)
        self.assertEqual(result["rpath"], ["/lib1", "/lib2", "/lib3"])
        self.assertEqual(result["runpath"], ["/run1", "/run2"])

    def test_reject_invalid_input_type(self):
        with self.assertRaises(ContractError) as ctx:
            parse_elf("not bytes")  # type: ignore[arg-type]
        self.assertEqual(ctx.exception.code, "INVALID_TYPE")

        with self.assertRaises(ContractError) as ctx:
            parse_elf(12345)  # type: ignore[arg-type]
        self.assertEqual(ctx.exception.code, "INVALID_TYPE")

        with self.assertRaises(ContractError) as ctx:
            parse_elf(None)  # type: ignore[arg-type]
        self.assertEqual(ctx.exception.code, "INVALID_TYPE")

    def test_reject_truncated_file(self):
        with self.assertRaises(ContractError) as ctx:
            parse_elf(b"")
        self.assertEqual(ctx.exception.code, "TRUNCATED_ELF")

        with self.assertRaises(ContractError) as ctx:
            parse_elf(b"\x7fELF" + b"\x00" * 20)
        self.assertEqual(ctx.exception.code, "TRUNCATED_ELF")

        elf_bytes = build_elf(machine="x86_64", needed=["libc.so.6"])
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes[:50])
        self.assertEqual(ctx.exception.code, "TRUNCATED_ELF")

    def test_reject_malformed_magic(self):
        elf_bytes = build_elf(magic=b"MZ\x90\x00")
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_unsupported_elf32(self):
        elf_bytes = build_elf(ei_class=1)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_ELF")

    def test_reject_unsupported_elf_class(self):
        elf_bytes = build_elf(ei_class=3)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_ELF")

    def test_reject_unsupported_big_endian(self):
        elf_bytes = build_elf(ei_data=2)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_ELF")

    def test_reject_unsupported_data_encoding(self):
        elf_bytes = build_elf(ei_data=0)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_ELF")

    def test_reject_invalid_ident_version(self):
        elf_bytes = build_elf(ei_version=2)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_invalid_header_version(self):
        elf_bytes = build_elf(e_version=0)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_invalid_ehsize(self):
        elf_bytes = build_elf(e_ehsize_override=50)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_unsupported_elf_type(self):
        # ET_REL = 1
        elf_bytes = build_elf(e_type_override=1)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_ELF")

        # ET_CORE = 4
        elf_bytes = build_elf(e_type_override=4)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_ELF")

    def test_reject_unsupported_machine_architecture(self):
        # EM_386 = 3 (x86 32-bit)
        elf_bytes = build_elf(e_machine_override=3)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_ELF")

        # EM_ARM = 40 (ARM 32-bit)
        elf_bytes = build_elf(e_machine_override=40)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_ELF")

        # EM_RISCV = 243
        elf_bytes = build_elf(e_machine_override=243)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "UNSUPPORTED_ELF")

    def test_reject_invalid_phentsize(self):
        elf_bytes = build_elf(e_phentsize_override=32)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_excessive_phnum(self):
        elf_bytes = build_elf(e_phnum_override=20000)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_truncated_program_header_table(self):
        elf_bytes = build_elf(e_phnum_override=5, truncate_bytes=40)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "TRUNCATED_ELF")

    def test_reject_segment_data_beyond_file_bounds(self):
        elf_bytes = build_elf(pt_load_filesz_override=999999, pt_load_memsz_override=999999)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "TRUNCATED_ELF")

    def test_reject_segment_filesz_exceeds_memsz(self):
        elf_bytes = build_elf(pt_load_filesz_override=1000, pt_load_memsz_override=500)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_multiple_pt_interp_segments(self):
        elf_bytes = build_elf(
            interpreter="/lib64/ld-linux-x86-64.so.2",
            duplicate_interpreter=True,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_multiple_pt_dynamic_segments(self):
        elf_bytes = build_elf(
            needed=["libc.so.6"],
            duplicate_dynamic=True,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_bad_interpreter_values(self):
        # Empty interpreter
        elf_bytes = build_elf(raw_interpreter=b"\x00")
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "INVALID_INTERPRETER")

        # Not null terminated
        elf_bytes = build_elf(raw_interpreter=b"/lib64/ld-linux-x86-64.so.2")
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "INVALID_INTERPRETER")

        # Relative path
        elf_bytes = build_elf(raw_interpreter=b"lib64/ld-linux-x86-64.so.2\x00")
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "INVALID_INTERPRETER")

        # Control characters
        elf_bytes = build_elf(raw_interpreter=b"/lib64/ld\n.so\x00")
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "INVALID_INTERPRETER")

        # Invalid UTF-8
        elf_bytes = build_elf(raw_interpreter=b"/\xff\xfe\x00")
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "INVALID_INTERPRETER")

    def test_reject_unaligned_dynamic_section(self):
        elf_bytes = build_elf(needed=["libc.so.6"], corrupt_dyn_size=5)
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_unmapped_virtual_address(self):
        elf_bytes = build_elf(
            needed=["libc.so.6"],
            corrupt_strtab_vaddr=0x99999999,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_missing_dynamic_string_table(self):
        elf_bytes = build_elf(
            needed=["libc.so.6"],
            omit_strtab_tag=True,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

        elf_bytes = build_elf(
            needed=["libc.so.6"],
            omit_strsz_tag=True,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_conflicting_dynamic_tags(self):
        elf_bytes = build_elf(
            soname="libone.so",
            conflicting_soname="libtwo.so",
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_corrupted_string_tables(self):
        # Does not start with null byte
        elf_bytes = build_elf(
            needed=["libc.so.6"],
            corrupt_strtab_start=True,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "INVALID_STRING_TABLE")

        # Unterminated string
        elf_bytes = build_elf(
            needed=["libc.so.6"],
            corrupt_strtab_unterminated=True,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_string_table_invalid_utf8(self):
        # Build an ELF and replace the needed library string with invalid UTF-8 bytes
        elf_bytes = build_elf(needed=["libc.so.6"])
        modified = bytearray(elf_bytes)
        idx = modified.find(b"libc.so.6\x00")
        self.assertNotEqual(idx, -1)
        modified[idx : idx + 4] = b"\xff\xfe\xff\xfe"
        with self.assertRaises(ContractError) as ctx:
            parse_elf(bytes(modified))
        self.assertEqual(ctx.exception.code, "INVALID_STRING_TABLE")

    def test_reject_version_needs_cycle(self):
        elf_bytes = build_elf(
            version_needs={
                "libc.so.6": ["GLIBC_2.2.5"],
                "libm.so.6": ["GLIBC_2.2.5"],
            },
            corrupt_verneed_loop=True,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_vernaux_cycle(self):
        elf_bytes = build_elf(
            version_needs={"libc.so.6": ["GLIBC_2.2.5", "GLIBC_2.14"]},
            corrupt_vernaux_loop=True,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_unsupported_verneed_version(self):
        elf_bytes = build_elf(
            version_needs={"libc.so.6": ["GLIBC_2.2.5"]},
            corrupt_verneed_version=2,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_verneed_premature_termination(self):
        elf_bytes = build_elf(
            version_needs={
                "libc.so.6": ["GLIBC_2.2.5"],
                "libm.so.6": ["GLIBC_2.2.5"],
            },
            corrupt_verneed_premature_end=True,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "TRUNCATED_ELF")

    def test_reject_vernaux_premature_termination(self):
        elf_bytes = build_elf(
            version_needs={"libc.so.6": ["GLIBC_2.2.5", "GLIBC_2.14"]},
            corrupt_vernaux_premature_end=True,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "TRUNCATED_ELF")

    def test_reject_verneed_missing_aux_offset(self):
        elf_bytes = build_elf(
            version_needs={"libc.so.6": ["GLIBC_2.2.5"]},
            corrupt_verneed_missing_aux=True,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_verneed_empty_filename(self):
        elf_bytes = build_elf(
            version_needs={"libc.so.6": ["GLIBC_2.2.5"]},
            corrupt_verneed_empty_filename=True,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_vernaux_empty_vername(self):
        elf_bytes = build_elf(
            version_needs={"libc.so.6": ["GLIBC_2.2.5"]},
            corrupt_vernaux_empty_vername=True,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "MALFORMED_ELF")

    def test_reject_truncated_section_header_table(self):
        elf_bytes = build_elf(
            include_section_headers=True,
            e_shnum_override=20,
        )
        with self.assertRaises(ContractError) as ctx:
            parse_elf(elf_bytes)
        self.assertEqual(ctx.exception.code, "TRUNCATED_ELF")


if __name__ == "__main__":
    unittest.main()
