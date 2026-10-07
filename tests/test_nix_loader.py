"""Direct-loader diagnostics preserve the boundary to native qualification."""
import json
from pathlib import Path
from subprocess import CompletedProcess
import tempfile
import unittest
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.nix_loader import check_glibc_abi, evaluate, glibc_definitions, loader_argv
from tests.elf_builder import build_elf


FACTS = {"loader": "/nix/store/pinned-glibc/lib/ld-linux-x86-64.so.2",
         "glibc_lib": "/nix/store/pinned-glibc/lib",
         "library_path": "/nix/store/pinned-glibc/lib:/nix/store/gtk/lib",
         "python": "/nix/store/python/bin/python3", "node": "/nix/store/node/bin/node",
         "readelf": "/nix/store/binutils/bin/readelf"}


class LoaderEvaluationTests(unittest.TestCase):
    def test_needs_do_not_establish_provider_capability(self):
        data = b"Version needs section '.gnu.version_r' contains 1 entry:\n Name: GLIBC_9.9\n"
        with self.assertRaises(ContractError):
            glibc_definitions(data)
        definitions = b"Version definition section '.gnu.version_d' contains 2 entries:\n Name: GLIBC_2.17\n Name: GLIBC_2.38\n"
        self.assertEqual(glibc_definitions(definitions + data), {"GLIBC_2.17", "GLIBC_2.38"})

    def test_abi_is_per_library_and_missing_versions_fail(self):
        needs = {"libc.so.6": ["GLIBC_2.38"], "libm.so.6": ["GLIBC_2.17"]}
        providers = {"libc.so.6": {"GLIBC_2.17", "GLIBC_2.38"}, "libm.so.6": {"GLIBC_2.17"}}
        self.assertEqual(check_glibc_abi(needs, providers)["status"], "compatible")
        with self.assertRaises(ContractError):
            check_glibc_abi(needs, {"libm.so.6": {"GLIBC_2.17", "GLIBC_2.38"}})

    def test_explicit_loader_preserves_arguments_and_requires_matching_store_libc(self):
        argv = loader_argv(FACTS, "/fixture/released-elf", ["arg with space", "--"])
        self.assertEqual(argv, [FACTS["loader"], "--argv0", "/fixture/released-elf", "--library-path",
                                FACTS["library_path"], "/fixture/released-elf", "arg with space", "--"])
        for changed in ({"loader": "/lib64/ld-linux-x86-64.so.2"},
                        {"glibc_lib": "/nix/store/different/lib"},
                        {"library_path": FACTS["library_path"] + ":/usr/lib"},
                        {"library_path": FACTS["library_path"] + ":/nix/store/gtk/../lib"}):
            with self.subTest(changed=changed), self.assertRaises(ContractError):
                loader_argv({**FACTS, **changed}, "/fixture/released-elf")

    def _evaluate(self, *, malformed=False, failure=False):
        with tempfile.TemporaryDirectory() as td:
            elf = Path(td) / "release-elf"
            original = build_elf(machine="x86_64", interpreter="/lib64/ld-linux-x86-64.so.2",
                                 version_needs={"libc.so.6": ["GLIBC_2.17"]})
            elf.write_bytes(original)
            calls = []
            def runner(argv, **kw):
                calls.append((argv, kw))
                if failure:
                    return CompletedProcess(argv, 1, b"", b"diagnostic failed")
                if "--list" in argv:
                    return CompletedProcess(argv, 0, b"libc.so.6 => pinned libc\n", b"")
                if "--version-info" in argv:
                    return CompletedProcess(argv, 0, b"Version definition section '.gnu.version_d' contains 1 entry:\n Name: GLIBC_2.17\n", b"")
                direct = "--argv0" in argv
                tool = "node" if "-e" in argv else "python"
                out = {"exe": FACTS["loader"] if direct else FACTS[tool]}
                if tool == "node":
                    out["execPath"] = out["exe"]
                return CompletedProcess(argv, 0, b"{}" if malformed else json.dumps(out).encode(), b"")
            result = evaluate(FACTS, [elf], prefix=["offline"],
                              env={"LD_LIBRARY_PATH": "/host/lib", "LD_PRELOAD": "/host/preload"}, runner=runner)
            self.assertEqual(elf.read_bytes(), original)
            self.assertTrue(all(c[0][0] == "offline" for c in calls))
            self.assertTrue(all("LD_LIBRARY_PATH" not in c[1]["env"] and "LD_PRELOAD" not in c[1]["env"] for c in calls))
            return result

    def test_executable_self_change_is_diagnostic_never_application_pass(self):
        result = self._evaluate()
        self.assertEqual(result["status"], "diagnostics-only")
        self.assertFalse(result["application_qualified"])
        self.assertFalse(result["sole_runtime_supported"])
        self.assertTrue(result["elfs"][0]["foreign_interpreter"])
        self.assertTrue(all(r["direct_self_is_loader"] for r in result["self_readers"]))
        self.assertNotIn("/fixture/", json.dumps(result))

    def test_malformed_and_failed_readback_do_not_yield_diagnostics_success(self):
        for kw in ({"malformed": True}, {"failure": True}):
            with self.subTest(kw=kw), self.assertRaises(ContractError):
                self._evaluate(**kw)


if __name__ == "__main__":
    unittest.main()
