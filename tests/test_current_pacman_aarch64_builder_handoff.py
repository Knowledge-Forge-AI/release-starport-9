"""Actual build_pacman_candidate handoff to the makepkg boundary (current pacman AArch64).

The unmodified builder and PKGBUILD renderer run from authenticated synthetic
captures through validate_build_inputs, payload extraction, offline npm closure
staging, ELF dependency policy and pacman provider queries. Each matrix case stops
at an intentional nonzero makepkg CommandReceipt (BUILD_FAILED). Nothing native
(makepkg, repo-add, pacman, GPG, Node) is executed.

Seams, all at authenticated-input or native-process boundaries:
- rs9.build_pacman.validate_build_inputs is *wrapped*, not replaced: the real
  function runs and the wrapper records the generation and context it received.
- rs9.build_native.bind_native_build_generation (current Burst/Nebular only):
  the source-owned current bootstrap cannot bind these historical-shaped
  synthetic captures, so the seam returns the authenticated intent version and
  records the generation. Current pure-JS Loom uses the real current binding via
  tests.test_current_native_version_propagation.current_cli.
- rs9.elf.parse_elf: public ELF facts (needed/interpreter) keyed by the e_machine
  of the actual bytes the builder read.
- CommandRunner: MockCommandRunner handlers for makepkg, pacman -Qo and repo-add.
- os.geteuid: pinned nonroot so the existing nonroot guard is host-independent.
"""

from __future__ import annotations

from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from rs9 import build_native
from rs9.build_native import CommandReceipt, MockCommandRunner
from rs9.build_pacman import build_pacman_candidate
from rs9.burst_native import BURST_CLOSED_PREBUILDS
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.errors import ContractError
from rs9.profiles import selection_for_intent
from rs9.release_core import authenticate_release
from tests.publication_fixtures import authorize_fixture_configuration
from tests.shadow_fixtures import fixture_evidence
from tests.test_build_native import create_cli_fixture
from tests.test_burst_platform_wheel import make_synthetic_elf, make_synthetic_macho
from tests.test_current_native_version_propagation import current_cli

BURST = "theme-forge-stellar-burst"
NEBULAR = "theme-forge-nebular-fusion"
LOOM = "theme-forge-stellar-loom"
NATIVE = (BURST, NEBULAR)

EM_X86_64, EM_AARCH64 = 62, 183
GLIBC_INTERPRETERS = {EM_X86_64: "/lib64/ld-linux-x86-64.so.2", EM_AARCH64: "/lib/ld-linux-aarch64.so.1"}
MUSL_INTERPRETERS = {EM_X86_64: "/lib/ld-musl-x86_64.so.1", EM_AARCH64: "/lib/ld-musl-aarch64.so.1"}

MAKEPKG_ARGV = ["makepkg", "--nodeps", "--noextract", "--force", "--clean"]
BASE_ENV = {"SOURCE_DATE_EPOCH": "1767225600"}
AARCH64_ENV = {"SOURCE_DATE_EPOCH": "1767225600", "PKGEXT": ".pkg.tar.zst"}
DEPENDS = {BURST: "depends=(glibc 'nodejs>=22')", NEBULAR: "depends=(bash glibc)", LOOM: "depends=('nodejs>=22')"}
MAKEPKG_STOP = b"==> ERROR: intentional fixture stop at the makepkg boundary\n"
REPO_ADD_STOP = b"intentional fixture stop before repository metadata\n"
TOOLS = {"makepkg": "/usr/bin/makepkg", "repo-add": "/usr/bin/repo-add", "pacman": "/usr/bin/pacman"}

MATRIX = (
    ("historical-burst-x86_64", BURST, "x86_64", HISTORICAL_GENERATION),
    ("historical-nebular-x86_64", NEBULAR, "x86_64", HISTORICAL_GENERATION),
    ("historical-loom-any", LOOM, "any", HISTORICAL_GENERATION),
    ("current-burst-x86_64", BURST, "x86_64", CURRENT_GENERATION),
    ("current-nebular-x86_64", NEBULAR, "x86_64", CURRENT_GENERATION),
    ("current-loom-any", LOOM, "any", CURRENT_GENERATION),
    ("current-burst-aarch64", BURST, "aarch64", CURRENT_GENERATION),
    ("current-nebular-aarch64", NEBULAR, "aarch64", CURRENT_GENERATION),
)


def pkgbuild_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        for key in ("pkgname", "pkgver", "pkgrel"):
            if line.startswith(key + "="):
                fields[key] = line.split("=", 1)[1]
        if line.startswith("arch=('") and line.endswith("')"):
            fields["arch"] = line[len("arch=('"):-2]
    return fields


def recording_runner(record: dict, *, emulate_makepkg_output: bool = False, output_names=None) -> MockCommandRunner:
    """Native process boundary. makepkg fails intentionally unless output emulation is asked.

    Output emulation follows makepkg's ${pkgname}-${pkgver}-${pkgrel}-${arch}${PKGEXT}
    naming from the PKGBUILD the builder actually wrote and the env it actually
    passed. It assumes a native host whose CARCH equals the rendered arch. If PKGEXT
    is unset it falls back to Arch x86_64's .pkg.tar.zst; ArchARM's default would
    be .xz, which is why the builder overrides PKGEXT.
    """

    def makepkg(argv, cwd=None, env=None):
        work = Path(cwd)
        text = (work / "PKGBUILD").read_text("utf-8")
        record["makepkg"].append({
            "argv": list(argv), "cwd": work, "env": None if env is None else dict(env), "pkgbuild": text,
            "src": sorted(p.relative_to(work / "src").as_posix() for p in (work / "src").rglob("*")),
        })
        if not emulate_makepkg_output:
            return CommandReceipt(argv, 2, b"", MAKEPKG_STOP, tool_name="makepkg")
        fields = pkgbuild_fields(text)
        name = (f"{fields['pkgname']}-{fields['pkgver']}-{fields['pkgrel']}-{fields['arch']}"
                f"{(env or {}).get('PKGEXT', '.pkg.tar.zst')}")
        for emitted in ([name] if output_names is None else output_names):
            (work / emitted).write_bytes(b"inert stub package bytes: " + emitted.encode())
        return CommandReceipt(argv, 0, b"", b"", tool_name="makepkg")

    def pacman(argv, cwd=None, env=None):
        if argv == ["pacman", "-Qo", "--quiet", "/usr/lib/libc.so.6"]:
            return CommandReceipt(argv, 0, b"glibc\n", b"", tool_name="pacman")
        return CommandReceipt(argv, 1, b"", b"error: no package owns the queried path\n", tool_name="pacman")

    def repo_add(argv, cwd=None, env=None):
        record["repo_add"].append({"argv": list(argv), "cwd": Path(cwd), "env": env,
                                   "staged": sorted(p.name for p in Path(cwd).iterdir())})
        return CommandReceipt(argv, 3, b"", REPO_ADD_STOP, tool_name="repo-add")

    return MockCommandRunner(available_tools=TOOLS,
                             handlers={"makepkg": makepkg, "pacman": pacman, "repo-add": repo_add})


class CurrentPacmanAarch64BuilderHandoffTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.fixtures: dict[tuple[str, str], tuple] = {}
        euid = patch("os.geteuid", return_value=1000)
        euid.start()
        self.addCleanup(euid.stop)

    # Fixtures: one authenticated capture per product shape, reused across runs so
    # PKGBUILD text can be compared byte-for-byte between generations/architectures.
    def fixture(self, product: str, generation: str):
        key = (product, "current" if product == LOOM and generation == CURRENT_GENERATION else "shared")
        if key not in self.fixtures:
            root = self.root / "fixtures" / "-".join(key)
            if product == BURST:
                binaries = {"darwin-arm64": make_synthetic_macho("arm64", 13, 0),
                            "darwin-x64": make_synthetic_macho("x86_64", 15, 0),
                            "linux-arm64-gnu": make_synthetic_elf("aarch64"),
                            "linux-x64-gnu": make_synthetic_elf("x86_64")}
                extra = [(path.removeprefix("package/"), binaries[k]) for k, path in BURST_CLOSED_PREBUILDS.items()]
                self.fixtures[key] = create_cli_fixture(root, product=BURST, extra_asset_entries=extra)
            elif product == NEBULAR:
                root.mkdir(parents=True)
                intent = fixture_evidence(root)
                capture = authenticate_release(selection_for_intent(intent), root)
                authorize_fixture_configuration(root, intent, capture)
                self.fixtures[key] = (capture, intent, None)
            elif key[1] == "current":
                capture, intent = current_cli(root, LOOM)
                self.fixtures[key] = (capture, intent, None)
            else:
                self.fixtures[key] = create_cli_fixture(root)
        return self.fixtures[key]

    def drive(self, label, product, arch, generation, *, interpreters=GLIBC_INTERPRETERS,
              needed=("libc.so.6",), emulate_makepkg_output=False, output_names=None, missing_provider=False):
        capture, intent, offline = self.fixture(product, generation)
        scratch = self.root / "runs" / label
        scratch.mkdir(parents=True)
        record = {"validate": [], "binding": [], "parsed": [], "makepkg": [], "repo_add": []}
        real_validate = build_native.validate_build_inputs
        real_binding = build_native.bind_native_build_generation
        seam_binding = product in NATIVE and generation == CURRENT_GENERATION

        def validate(*args, **kwargs):
            entry = {"arch": args[2], "kwargs": dict(kwargs)}
            record["validate"].append(entry)
            entry["ctx"] = real_validate(*args, **kwargs)
            return entry["ctx"]

        def binding(capture_arg, intent_arg, *, generation):
            record["binding"].append(generation)
            self.assertIs(capture_arg, capture)
            if seam_binding:
                return intent_arg["version"]
            return real_binding(capture_arg, intent_arg, generation=generation)

        def parse(data):
            machine = struct.unpack_from("<H", data, 18)[0]
            record["parsed"].append(machine)
            return {"needed": list(needed), "interpreter": interpreters[machine]}

        runner = recording_runner(record, emulate_makepkg_output=emulate_makepkg_output,
                                  output_names=output_names)
        if missing_provider:
            runner.handlers["pacman"] = lambda argv, **kwargs: CommandReceipt(argv, 1, b"", b"provider absent", tool_name="pacman")
        kwargs = {} if generation == HISTORICAL_GENERATION else {"generation": generation}
        with patch("rs9.build_pacman.validate_build_inputs", side_effect=validate), \
                patch("rs9.build_native.bind_native_build_generation", side_effect=binding), \
                patch("rs9.elf.parse_elf", side_effect=parse):
            with self.assertRaises(ContractError) as caught:
                build_pacman_candidate(capture, intent, arch, scratch, offline_npm_archives=offline,
                                       runner=runner, **kwargs)
        return {"error": caught.exception, "record": record, "runner": runner,
                "scratch": scratch, "capture": capture, "intent": intent}

    def pkgbuild_line(self, text, prefix):
        lines = [line for line in text.splitlines() if line.startswith(prefix)]
        self.assertEqual(len(lines), 1, (prefix, text))
        return lines[0]

    def test_current_arm_missing_installed_provider_stops_before_makepkg_and_catalogue(self):
        for product in NATIVE:
            with self.subTest(product=product):
                result = self.drive("missing-" + product, product, "aarch64", CURRENT_GENERATION, missing_provider=True)
                self.assertEqual(result["error"].code, "DEPENDENCY_DERIVATION")
                self.assertEqual(result["record"]["makepkg"], [])
                calls = [row["argv"] for row in result["runner"].calls if row["argv"][0] == "pacman"]
                self.assertEqual(calls, [["pacman", "-Qo", "--quiet", "/usr/lib/libc.so.6"]])

    def test_old_routes_keep_original_catalogue_fallback(self):
        result = self.drive("old-provider", sorted(NATIVE)[0], "x86_64", HISTORICAL_GENERATION, missing_provider=True)
        self.assertEqual([row["argv"][1] for row in result["runner"].calls if row["argv"][0] == "pacman"], ["-Qo", "-F"])

    def test_makepkg_boundary_matrix(self):
        results = {}
        for label, product, arch, generation in MATRIX:
            with self.subTest(case=label):
                run = results[label] = self.drive(label, product, arch, generation)
                record, scratch, intent = run["record"], run["scratch"], run["intent"]
                error = run["error"]
                self.assertEqual(error.code, "BUILD_FAILED")
                self.assertIn("makepkg failed with exit code 2", error.message)
                self.assertIn(MAKEPKG_STOP.decode().strip(), error.message)

                # Generation and architecture recorded at the actual validate_build_inputs call.
                self.assertEqual(len(record["validate"]), 1)
                call = record["validate"][0]
                self.assertEqual(call["arch"], arch)
                self.assertEqual(call["kwargs"]["generation"], generation)
                self.assertEqual(call["kwargs"]["adapter"], "pacman")
                ctx = call["ctx"]
                self.assertEqual(ctx["arch"], arch)
                self.assertEqual(ctx["project_id"], product)
                self.assertEqual(record["binding"],
                                 [] if generation == HISTORICAL_GENERATION else [CURRENT_GENERATION])

                # Exact makepkg boundary: argv, cwd, env.
                self.assertEqual(len(record["makepkg"]), 1)
                seen = record["makepkg"][0]
                self.assertEqual(seen["argv"], [a for a in MAKEPKG_ARGV if a != "--nodeps"] if arch == "aarch64" else MAKEPKG_ARGV)
                self.assertEqual(seen["cwd"], scratch / "pacman" / product)
                self.assertEqual(seen["env"], AARCH64_ENV if arch == "aarch64" else BASE_ENV)
                self.assertNotIn("--ignorearch", seen["argv"])
                if arch == "aarch64":
                    self.assertFalse(set(seen["argv"]) & {"--nodeps", "-d", "--skipinteg", "--skippgpcheck", "--skipchecksums", "-A", "--ignorearch"})
                self.assertFalse(any("CARCH" in item for item in seen["argv"]))
                self.assertFalse(any("CARCH" in k or "CARCH" in v for k, v in seen["env"].items()))

                # Actual rendered PKGBUILD text.
                text = seen["pkgbuild"]
                self.assertEqual(self.pkgbuild_line(text, "arch="), f"arch=('{arch}')")
                self.assertEqual(self.pkgbuild_line(text, "pkgname="), f"pkgname={product}")
                self.assertEqual(self.pkgbuild_line(text, "pkgver="), f"pkgver={intent['version']}")
                self.assertEqual(self.pkgbuild_line(text, "pkgrel="), "pkgrel=1")
                self.assertEqual(self.pkgbuild_line(text, "depends="), DEPENDS[product])
                self.assertNotIn("CARCH", text)

                # Native dependency facts came from bytes of the selected architecture,
                # and the provider came from a pacman receipt at the process boundary.
                pacman_calls = [c for c in run["runner"].calls if c["argv"][0] == "pacman"]
                if product in NATIVE:
                    machine = EM_AARCH64 if arch == "aarch64" else EM_X86_64
                    self.assertTrue(record["parsed"])
                    self.assertEqual(set(record["parsed"]), {machine})
                    self.assertEqual(pacman_calls, [{"argv": ["pacman", "-Qo", "--quiet", "/usr/lib/libc.so.6"],
                                                     "cwd": None, "env": None}])
                else:
                    self.assertEqual(record["parsed"], [])
                    self.assertEqual(pacman_calls, [])

                # Stopped before any artifact or repository step; repo dir keyed by ctx arch.
                self.assertEqual(record["repo_add"], [])
                self.assertEqual(list((scratch / "repo" / arch).iterdir()), [])
                self.assertEqual(sorted(p.name for p in (scratch / "repo").iterdir()), [arch])
                self.assertFalse((scratch / "pacman-manifest.json").exists())
                self.assertFalse(any(p.name.endswith((".pkg.tar.zst", ".pkg.tar.xz", ".pkg.tar.gz"))
                                     for p in scratch.rglob("*")))

        self.assertEqual({tuple(r["record"]["makepkg"][0]["argv"]) for r in results.values()},
                         {tuple(MAKEPKG_ARGV), tuple(a for a in MAKEPKG_ARGV if a != "--nodeps")})

        def pkgbuild(label):
            return results[label]["record"]["makepkg"][0]["pkgbuild"]

        def differing(a, b):
            left, right = pkgbuild(a).splitlines(), pkgbuild(b).splitlines()
            self.assertEqual(len(left), len(right))
            return {(x, y) for x, y in zip(left, right) if x != y}

        # Historical x86_64 recipes are unchanged by selecting the current generation.
        for product in NATIVE:
            short = "burst" if product == BURST else "nebular"
            self.assertEqual(pkgbuild(f"historical-{short}-x86_64"), pkgbuild(f"current-{short}-x86_64"))

        # Burst: one cross-platform release tarball; AArch64 changes only the arch line.
        self.assertEqual(differing("current-burst-x86_64", "current-burst-aarch64"),
                         {("arch=('x86_64')", "arch=('aarch64')")})
        burst_ctx = results["current-burst-aarch64"]["record"]["validate"][0]["ctx"]
        arm_prebuild = BURST_CLOSED_PREBUILDS["linux-arm64-gnu"]
        self.assertEqual(burst_ctx["burst_prebuild_info"]["target_path"], arm_prebuild)
        burst_src = results["current-burst-aarch64"]["record"]["makepkg"][0]["src"]
        self.assertIn(arm_prebuild, burst_src)
        self.assertIn(BURST_CLOSED_PREBUILDS["linux-x64-gnu"], burst_src)  # foreign retained inert
        self.assertIn("node_modules/min-dep/package.json", burst_src)

        # Nebular: the exact AArch64 release payload replaces only source/checksum/arch.
        neb_ctx = results["current-nebular-aarch64"]["record"]["validate"][0]["ctx"]
        self.assertEqual(neb_ctx["payload"]["id"], "linux-arm64")
        changed = differing("current-nebular-x86_64", "current-nebular-aarch64")
        self.assertEqual({new.split("=", 1)[0] for _, new in changed}, {"arch", "source", "sha256sums"})
        neb_text = pkgbuild("current-nebular-aarch64")
        self.assertEqual(self.pkgbuild_line(neb_text, "source="),
                         "source=(theme-forge-nebular-fusion-v0.6.1-aarch64-unknown-linux-gnu.tar.gz "
                         "theme-forge-nebular-fusion.desktop icon.png)")
        self.assertTrue(self.pkgbuild_line(neb_text, "sha256sums=").startswith(
            f"sha256sums=('{neb_ctx['payload']['sha256']}' "))
        self.assertIn('ln -s "/usr/lib/theme-forge-nebular-fusion/bin/tfnf" "$pkgdir/usr/bin/tfnf"', neb_text)

    def test_aarch64_package_naming_reaches_repo_add_boundary(self):
        """Post-makepkg: the builder locates and stages the makepkg-named AArch64 package.

        The stub derives the file name from the PKGBUILD and env actually handed to
        makepkg; repo-add then fails intentionally, so no repository DB is written.
        """
        expected = {BURST: "theme-forge-stellar-burst-0.6.1-1-aarch64.pkg.tar.zst",
                    NEBULAR: "theme-forge-nebular-fusion-0.6.1-1-aarch64.pkg.tar.zst"}
        for product in NATIVE:
            with self.subTest(product=product):
                run = self.drive("post-build-" + product, product, "aarch64", CURRENT_GENERATION,
                                 emulate_makepkg_output=True)
                error, record, scratch = run["error"], run["record"], run["scratch"]
                self.assertEqual(error.code, "BUILD_FAILED")
                self.assertIn("repo-add failed with exit code 3", error.message)
                self.assertEqual(record["makepkg"][0]["env"], AARCH64_ENV)

                work = scratch / "pacman" / product
                produced = [p.name for p in work.iterdir() if p.name.endswith(".pkg.tar.zst")]
                self.assertEqual(produced, [expected[product]])
                repo_dir = scratch / "repo" / "aarch64"
                staged = repo_dir / expected[product]
                self.assertEqual(len(record["repo_add"]), 1)
                call = record["repo_add"][0]
                self.assertEqual(call["argv"], ["repo-add", str(repo_dir / "custom.db.tar.gz"), str(staged)])
                self.assertEqual(call["cwd"], repo_dir)
                self.assertIsNone(call["env"])
                self.assertEqual(call["staged"], [expected[product]])
                self.assertEqual(staged.read_bytes(), (work / expected[product]).read_bytes())
                self.assertFalse((repo_dir / "custom.db.tar.gz").exists())
                self.assertFalse((scratch / "pacman-manifest.json").exists())
                self.assertEqual(sorted(p.name for p in (scratch / "repo").iterdir()), ["aarch64"])

    def test_current_aarch64_refuses_foreign_ambiguous_or_wrong_format_output(self):
        for product in NATIVE:
            stem = f"{product}-0.6.1-1"
            correct = stem + "-aarch64.pkg.tar.zst"
            cases = {
                "foreign": [stem + "-x86_64.pkg.tar.zst"],
                "revision": [f"{product}-0.6.1-2-aarch64.pkg.tar.zst"],
                "version-prefix": [f"{product}-0.6.10-1-aarch64.pkg.tar.zst"],
                "xz": [stem + "-aarch64.pkg.tar.xz"],
                "ambiguous": [correct, stem + "-x86_64.pkg.tar.zst"],
                "absent": [],
            }
            for label, names in cases.items():
                with self.subTest(product=product, case=label):
                    run = self.drive("identity-" + product + "-" + label, product, "aarch64",
                                     CURRENT_GENERATION, emulate_makepkg_output=True, output_names=names)
                    self.assertEqual(run["error"].code, "BUILD_FAILED")
                    self.assertIn("exact package identity", run["error"].message)
                    self.assertEqual(len(run["record"]["makepkg"]), 1)
                    self.assertEqual(run["record"]["repo_add"], [])
                    self.assertEqual(list((run["scratch"] / "repo" / "aarch64").iterdir()), [])

    def test_arm_interpreter_dependency_policy_through_builder(self):
        """With no DT_NEEDED, glibc in depends is attributable only to the ARM interpreter."""
        expected = {
            (BURST, "glibc"): "depends=(glibc 'nodejs>=22')",
            (BURST, "musl"): "depends=('nodejs>=22')",
            (NEBULAR, "glibc"): "depends=(bash glibc)",
            (NEBULAR, "musl"): "depends=(bash)",
        }
        for (product, libc), depends in expected.items():
            with self.subTest(product=product, interpreter=libc):
                interpreters = GLIBC_INTERPRETERS if libc == "glibc" else MUSL_INTERPRETERS
                run = self.drive(f"interp-{libc}-{product}", product, "aarch64", CURRENT_GENERATION,
                                 interpreters=interpreters, needed=())
                self.assertEqual(run["error"].code, "BUILD_FAILED")
                self.assertTrue(run["record"]["parsed"])
                self.assertEqual(set(run["record"]["parsed"]), {EM_AARCH64})
                text = run["record"]["makepkg"][0]["pkgbuild"]
                self.assertEqual(self.pkgbuild_line(text, "depends="), depends)
                self.assertEqual(self.pkgbuild_line(text, "arch="), "arch=('aarch64')")
                self.assertEqual([c["argv"][0] for c in run["runner"].calls], ["makepkg"])


if __name__ == "__main__":
    unittest.main()
