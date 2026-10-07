"""Unit tests for the experimental PRoot pins, guest-only argv contract and falsifiable probes."""
import errno
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.nix_proot import (
    FACTS_SCHEMA,
    GATES,
    GUEST_ENVIRONMENT_KEYS,
    REQUIRED_FACT_KEYS,
    GuestLayout,
    GuestRuntime,
    PROOT_NIXPKGS_REVISION,
    PROOT_RECIPE_BLOB,
    PROOT_SOURCE_HASH,
    PROOT_VERSION,
    SCHEMA,
    evaluate_proot_experiment,
    guest_bindings,
    observe_native,
    prepare_layout,
    probe_args_exit_signals_orphans,
    probe_closure_resolution,
    probe_descendant_interpreter,
    probe_executable_self,
    probe_in_guest_offline,
    probe_no_userns_ptrace,
    probe_pinned_derivation,
    probe_verifier_and_smoke,
    probe_webkit_sandbox_state,
    proot_command_argv,
    read_closure,
    validate_proot_facts,
    verify_closure,
    verify_pinned_proot,
    wrapper_script,
)

COUNTER = itertools.count(1)


def store(name):
    """Unique syntactically valid store path; digits are inside the Nix base-32 alphabet."""
    return "/nix/store/" + format(next(COUNTER), "032d") + "-" + name


def make_facts(system="x86_64-linux"):
    arm = system == "aarch64-linux"
    glibc = store("glibc-2.40-66")
    gtk = store("gtk3-3.24.43")
    env = store("rs9-nebular-proot-guest-env")
    library_path = glibc + "/lib:" + gtk + "/lib"
    facts = {
        "schema": FACTS_SCHEMA,
        "system": system,
        "proot": store("proot-5.4.0") + "/bin/proot",
        "proot_version": PROOT_VERSION,
        "proot_nixpkgs_rev": PROOT_NIXPKGS_REVISION,
        "proot_recipe_blob": PROOT_RECIPE_BLOB,
        "proot_recipe_file": store("package.nix"),
        "proot_source_hash": PROOT_SOURCE_HASH,
        "guest_root": store("rs9-nebular-proot-guest-root"),
        "guest_env": env,
        "guest_path": env + "/bin",
        "guest_environment": {
            "PATH": env + "/bin",
            "LD_LIBRARY_PATH": library_path,
            "FONTCONFIG_FILE": store("fonts.conf"),
            "GIO_EXTRA_MODULES": store("glib-networking-2.80") + "/lib/gio/modules",
            "GDK_PIXBUF_MODULE_FILE": store("gdk-pixbuf-2.42.12") + "/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache",
            "XDG_DATA_DIRS": store("shared-mime-info-2.4") + "/share:" + store("adwaita-icon-theme-47") + "/share",
        },
        "closure_paths_file": store("closure-info") + "/store-paths",
        "loader": glibc + "/lib/" + ("ld-linux-aarch64.so.1" if arm else "ld-linux-x86-64.so.2"),
        "foreign_interpreter": "/lib/ld-linux-aarch64.so.1" if arm else "/lib64/ld-linux-x86-64.so.2",
        "glibc_lib": glibc + "/lib",
        "library_path": library_path,
        "env": store("coreutils-9.5") + "/bin/env",
        "sh": store("bash-5.2p37") + "/bin/sh",
        "python": store("python3-3.12.8") + "/bin/python3",
        "node": store("nodejs-22.12.0") + "/bin/node",
        "readelf": store("binutils-2.43.1") + "/bin/readelf",
        "ldd": store("glibc-2.40-66-bin") + "/bin/ldd",
        "xvfb_run": store("xvfb-run-1") + "/bin/xvfb-run",
        "dbus_run_session": store("dbus-1.14.10") + "/bin/dbus-run-session",
        "bwrap": store("bubblewrap-0.10.0") + "/bin/bwrap",
        "launcher": store("rs9-nebular-proot-launch"),
    }
    return facts


def closure_for(facts):
    host_only = {"proot", "proot_recipe_file", "guest_root", "closure_paths_file"}
    visible = [v for k, v in facts.items()
               if isinstance(v, str) and v.startswith("/nix/store/") and k not in host_only]
    visible += facts["library_path"].split(":")
    for value in facts["guest_environment"].values():
        visible += value.split(":")
    return sorted({"/".join(p.split("/")[:4]) for p in visible})


def completed(argv, code=0, out=b"", err=b""):
    return subprocess.CompletedProcess(argv, code, stdout=out, stderr=err)


class RecipePinTests(unittest.TestCase):
    def test_pinned_proot_constants(self):
        self.assertEqual(PROOT_VERSION, "5.4.0")
        self.assertEqual(PROOT_NIXPKGS_REVISION, "0921fdb3e13e40fe25fbc52b89661a9d6d32ac68")
        self.assertEqual(PROOT_RECIPE_BLOB, "02766094fbf82ab7ee4425a14d480f061cbcdadc")
        self.assertEqual(PROOT_SOURCE_HASH, "sha256-Z9Y7ccWp5KEVuo9xfHcgo58XqYVdFo7ck1jH7cnT2KA=")

    def test_tampered_recipe_rejected_by_git_blob(self):
        tampered = b'stdenv.mkDerivation { version = "5.4.0"; hash = "' + PROOT_SOURCE_HASH.encode() + b'"; }'
        with self.assertRaises(ContractError) as ctx:
            verify_pinned_proot(tampered)
        self.assertEqual(ctx.exception.code, "PROOT_BLOB_MISMATCH")

    def test_recipe_matching_the_pinned_blob_is_accepted_and_content_checked(self):
        recipe = f'{{ version = "{PROOT_VERSION}"; hash = "{PROOT_SOURCE_HASH}"; }}\n'.encode()
        blob = hashlib.sha1(b"blob %d\0" % len(recipe) + recipe).hexdigest()
        with patch("rs9.nix_proot.PROOT_RECIPE_BLOB", blob):
            self.assertEqual(verify_pinned_proot(recipe)["git_blob"], blob)
            self.assertEqual(probe_pinned_derivation(recipe)["status"], "pass")
            wrong_version = recipe.replace(b"5.4.0", b"5.3.0")
        blob = hashlib.sha1(b"blob %d\0" % len(wrong_version) + wrong_version).hexdigest()
        with patch("rs9.nix_proot.PROOT_RECIPE_BLOB", blob):
            with self.assertRaises(ContractError) as ctx:
                verify_pinned_proot(wrong_version)
        self.assertEqual(ctx.exception.code, "PROOT_VERSION_MISMATCH")

    def test_probe_fails_or_is_not_run_but_never_passes_without_recipe_bytes(self):
        self.assertEqual(probe_pinned_derivation(None)["status"], "not-run")
        failed = probe_pinned_derivation(b"wrong recipe")
        self.assertEqual((failed["status"], failed["reason"]), ("fail", "PROOT_BLOB_MISMATCH"))


ROOT = Path(__file__).resolve().parents[1]


class NixSourceTests(unittest.TestCase):
    """The experimental recipe cannot be evaluated here; these keep its source honest against the Python contract."""

    def setUp(self):
        self.recipe = (ROOT / "nix/nebular-proot-experiment.nix").read_text()
        self.flake = (ROOT / "flake.nix").read_text()

    def test_pins_are_asserted_at_evaluation_not_merely_recorded(self):
        for pinned in (PROOT_VERSION, PROOT_NIXPKGS_REVISION, PROOT_RECIPE_BLOB, PROOT_SOURCE_HASH):
            self.assertIn(pinned, self.recipe)
        for assertion in ("assert nixpkgsRev == pin.rev;", "assert proot.version == pin.version;",
                          "assert recipeSourceHash == pin.sourceHash;", "assert builtins.pathExists recipePath;",
                          "assert stdenv.hostPlatform.isLinux;"):
            self.assertIn(assertion, self.recipe)
        self.assertIn("proot = pkgs.proot;", self.recipe)

    def test_facts_keys_match_the_python_contract_exactly(self):
        block = self.recipe.split("builtins.toJSON {", 1)[1].split("});", 1)[0]
        keys = set(re.findall(r"(?m)^    (\w+) = ", block)) | set(re.findall(r"(?m)^    inherit (\w+);", block))
        self.assertEqual(keys, set(REQUIRED_FACT_KEYS))
        nested = set(re.findall(r"(?m)^      (\w+) = ", block))
        self.assertEqual(nested, set(GUEST_ENVIRONMENT_KEYS))
        self.assertIn('schema = "' + FACTS_SCHEMA + '";', self.recipe)

    def test_no_private_paths_host_binds_or_guessed_cache_in_the_source(self):
        for forbidden in ("/" + "Users/", "inbox", "Documents/agent", "-b /etc", "-b /tmp", "-b /nix/store",
                          "/nix/store:/nix/store", "$HOME", "XDG_RUNTIME_DIR", "LD_PRELOAD"):
            self.assertNotIn(forbidden, self.recipe)

    def test_guest_root_is_closed_and_the_closure_is_exactly_what_gets_bound(self):
        self.assertIn("closureInfo", self.recipe)
        self.assertIn("rootPaths", self.recipe)
        self.assertIn('closure_paths_file = "${closure}/store-paths";', self.recipe)
        self.assertIn(': > "$out/etc/passwd"', self.recipe)
        self.assertNotIn("ln -s /etc", self.recipe)

    def test_experiment_is_a_separate_linux_only_output_that_legacy_outputs_never_reach(self):
        self.assertIn("experiments = perLinuxSystem", self.flake)
        head = self.flake.split("experiments = perLinuxSystem", 1)[0]
        self.assertIn("candidates = perSystem build;", head)
        self.assertIn("checks = perSystem (system: build system);", head)
        self.assertNotIn("proot", head.lower())
        self.assertIn("nixpkgsRev = nixpkgs.rev or null;", self.flake)
        self.assertIn('inputs.nixpkgs.url = "github:NixOS/nixpkgs/' + PROOT_NIXPKGS_REVISION + '";', self.flake)


class FactsAndClosureTests(unittest.TestCase):
    def setUp(self):
        self.facts = make_facts()

    def test_valid_facts_for_both_linux_systems(self):
        self.assertIs(validate_proot_facts(self.facts), self.facts)
        arm = make_facts("aarch64-linux")
        self.assertEqual(validate_proot_facts(arm)["foreign_interpreter"], "/lib/ld-linux-aarch64.so.1")

    def test_fact_corruptions_are_rejected(self):
        arm = make_facts("aarch64-linux")
        cases = {
            "missing-key": {k: v for k, v in self.facts.items() if k != "ldd"},
            "extra-key": dict(self.facts, extra="x"),
            "schema": dict(self.facts, schema="rs9.nix-proot-facts.v1"),
            "host-proot": dict(self.facts, proot="/usr/bin/proot"),
            "dotdot": dict(self.facts, python=self.facts["python"].replace("/bin/", "/../bin/")),
            "null-byte": dict(self.facts, node=self.facts["node"] + "\x00"),
            "fake-version": dict(self.facts, proot_version="5.3.0"),
            "fake-rev": dict(self.facts, proot_nixpkgs_rev="0" * 40),
            "fake-blob": dict(self.facts, proot_recipe_blob="0" * 40),
            "fake-source-hash": dict(self.facts, proot_source_hash="sha256-" + "A" * 43 + "="),
            "wrong-interpreter": dict(self.facts, foreign_interpreter="/lib/ld-linux-aarch64.so.1"),
            "loader-not-in-glibc": dict(self.facts, glibc_lib=store("other-glibc") + "/lib"),
            "arm-with-x86-loader": dict(arm, loader=self.facts["loader"]),
            "host-library-path": dict(self.facts, library_path=self.facts["library_path"] + ":/usr/lib"),
            "unknown-system": dict(self.facts, system="aarch64-darwin"),
        }
        for name, bad in cases.items():
            with self.subTest(name):
                with self.assertRaises(ContractError):
                    validate_proot_facts(bad)

    def test_guest_environment_must_be_the_pinned_closure(self):
        env = dict(self.facts["guest_environment"], LD_LIBRARY_PATH=store("unpinned") + "/lib")
        with self.assertRaises(ContractError):
            validate_proot_facts(dict(self.facts, guest_environment=env))
        env = dict(self.facts["guest_environment"], HOST_VAR=store("x"))
        with self.assertRaises(ContractError):
            validate_proot_facts(dict(self.facts, guest_environment=env))

    def test_closure_covers_every_guest_visible_fact(self):
        closure = closure_for(self.facts)
        self.assertEqual(verify_closure(self.facts, closure), closure)
        with self.assertRaises(ContractError) as ctx:
            verify_closure(self.facts, [p for p in closure if p != "/".join(self.facts["python"].split("/")[:4])])
        self.assertEqual(ctx.exception.code, "NIX_PROOT_CLOSURE")

    def test_closure_rejects_non_top_level_empty_and_duplicate_paths(self):
        closure = closure_for(self.facts)
        for bad in ([], closure + [closure[0]], [*closure, closure[0] + "/bin"], [*closure, "/usr/lib"]):
            with self.assertRaises(ContractError):
                verify_closure(self.facts, bad)

    def test_read_closure_reads_the_listing_and_fails_closed_when_unreadable(self):
        closure = closure_for(self.facts)
        with patch.object(Path, "read_text", return_value="\n".join([*closure, ""])):
            self.assertEqual(read_closure(self.facts), closure)
        with patch.object(Path, "read_text", side_effect=OSError):
            with self.assertRaises(ContractError):
                read_closure(self.facts)


class ArgvTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name).resolve()
        self.facts = make_facts()
        self.closure = closure_for(self.facts)
        self.smoke = self.base / "smoke"
        self.smoke.mkdir()
        self.layout = prepare_layout(self.base / "guest", self.base / "cache", workspaces=(self.smoke,))

    def test_layout_is_explicit_and_identity_files_use_the_real_ids(self):
        passwd = (self.layout.etc_dir / "passwd").read_text()
        self.assertIn(f":{os.getuid()}:{os.getgid()}:", passwd)
        self.assertEqual((self.layout.etc_dir / "group").read_text(), f"rs9:x:{os.getgid()}:\n")
        self.assertTrue(self.layout.cache_dir.is_dir())
        self.assertTrue((self.layout.tmp_dir / "home").is_dir())

    def test_bindings_are_only_closure_state_and_needed_devices(self):
        binds = guest_bindings(self.layout, self.closure, exists=lambda p: p in {"/dev/null", "/dev/shm"})
        targets = [t for _, t in binds]
        for path in self.closure:
            self.assertIn((path, path), binds)
        self.assertEqual(len(binds), len(self.closure) + 4 + 2 + 2)
        for broad in ("/nix/store", "/etc", "/nix", "/usr", "/lib", "/lib64", "/home", "/sys", "/run"):
            self.assertNotIn(broad, targets)
        self.assertNotIn(("/tmp", "/tmp"), binds)
        self.assertIn((str(self.layout.tmp_dir), "/tmp"), binds)
        self.assertIn((str(self.layout.etc_dir / "passwd"), "/etc/passwd"), binds)
        self.assertIn((str(self.layout.cache_dir), str(self.layout.cache_dir)), binds)
        self.assertIn((str(self.smoke), str(self.smoke)), binds)
        self.assertIn(("/dev/null", "/dev/null"), binds)
        self.assertNotIn("/dev/dri", targets)

    def test_display_and_dbus_are_bound_only_when_actually_provided(self):
        xdg, sock = self.base / "run", self.base / "bus"
        layout = GuestLayout(self.layout.cache_dir, self.layout.tmp_dir, self.layout.loader_tmp, self.layout.etc_dir,
                             x11_dir=self.base / "x11", dbus_socket=sock, xdg_runtime_dir=xdg)
        binds = guest_bindings(layout, self.closure, exists=lambda p: False)
        self.assertIn((str(self.base / "x11"), "/tmp/.X11-unix"), binds)
        self.assertIn((str(sock), str(sock)), binds)
        self.assertIn((str(xdg), str(xdg)), binds)
        plain = guest_bindings(self.layout, self.closure, exists=lambda p: False)
        self.assertFalse([t for _, t in plain if "X11" in t])

    def test_broad_or_ambiguous_bind_sources_are_refused(self):
        for bad in ("/tmp", "/etc", "/nix/store", "/", "/home", "relative", "/a:b", "/a/../b"):
            layout = GuestLayout(Path(bad), self.layout.tmp_dir, self.layout.loader_tmp, self.layout.etc_dir)
            with self.subTest(bad):
                with self.assertRaises(ContractError) as ctx:
                    guest_bindings(layout, self.closure, exists=lambda p: False)
                self.assertEqual(ctx.exception.code, "NIX_PROOT_BIND")

    def test_conflicting_guest_target_is_refused(self):
        layout = GuestLayout(self.layout.cache_dir, self.layout.tmp_dir, self.layout.loader_tmp, self.layout.etc_dir,
                             workspaces=(self.base / "a",))
        # A second source claiming the guest /tmp that the explicit scratch already owns.
        with patch("rs9.nix_proot._bind_source", side_effect=lambda p: "/tmp" if Path(p) == self.base / "a" else str(p)):
            with self.assertRaises(ContractError) as ctx:
                guest_bindings(layout, self.closure, exists=lambda p: False)
        self.assertEqual(ctx.exception.code, "NIX_PROOT_BIND")

    def test_guest_invocation_scrubs_host_state_and_sets_the_guest_root(self):
        host = {"PATH": "/usr/bin", "HOME": "/host-home", "LD_LIBRARY_PATH": "/usr/lib", "LD_PRELOAD": "/x.so",
                "THEME_FORGE_CACHE_DIR": str(self.layout.cache_dir), "LANG": "C.UTF-8", "DISPLAY": ":0",
                "XDG_RUNTIME_DIR": "/run/user/1000", "GITHUB_TOKEN": "secret"}
        argv, guest, count = proot_command_argv(self.facts, self.layout, self.closure, ["node", "-v"], env=host)
        self.assertEqual(argv[0], self.facts["env"])
        self.assertEqual(argv[1], f"PROOT_TMP_DIR={self.layout.loader_tmp}")
        self.assertEqual(argv[2], self.facts["proot"])
        self.assertEqual(argv[argv.index("-r") + 1], self.facts["guest_root"])
        self.assertIn("--kill-on-exit", argv)
        self.assertEqual(argv[argv.index("-w") + 1], "/tmp")
        self.assertEqual(argv[-2:], ["node", "-v"])
        self.assertEqual(argv.count("-b"), count)
        guest_part = argv[argv.index("-i") + 1:-2]
        self.assertEqual(guest_part, [f"{k}={v}" for k, v in sorted(guest.items())])
        self.assertEqual(guest["LD_LIBRARY_PATH"], self.facts["library_path"])
        self.assertEqual(guest["PATH"], self.facts["guest_path"])
        self.assertEqual(guest["HOME"], "/tmp/home")
        self.assertEqual(guest["THEME_FORGE_CACHE_DIR"], str(self.layout.cache_dir))
        self.assertEqual(guest["LANG"], "C.UTF-8")
        for leaked in ("DISPLAY", "XDG_RUNTIME_DIR", "GITHUB_TOKEN", "LD_PRELOAD"):
            self.assertNotIn(leaked, guest)
        self.assertNotIn("/usr/lib", " ".join(argv))
        self.assertNotIn("/nix/store:/nix/store", argv)
        self.assertNotIn("/etc:/etc", argv)
        self.assertNotIn("/tmp:/tmp", argv)
        self.assertNotIn("/host-home", " ".join(argv))

    def test_cache_is_explicit_never_guessed_from_home(self):
        with self.assertRaises(ContractError) as ctx:
            proot_command_argv(self.facts, self.layout, self.closure, ["true"],
                               env={"THEME_FORGE_CACHE_DIR": "/host-home/.cache/theme-forge-nebular-fusion"})
        self.assertEqual(ctx.exception.code, "PROOT_ENV_CACHE")

    def test_webkit_sandbox_override_is_refused_but_forcing_it_on_is_allowed(self):
        for env in ({"WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS": "1"}, {"WEBKIT_FORCE_SANDBOX": "0"}):
            with self.assertRaises(ContractError) as ctx:
                proot_command_argv(self.facts, self.layout, self.closure, ["true"], env=env)
            self.assertEqual(ctx.exception.code, "PROOT_ENV_SANDBOX")
        _, guest, _ = proot_command_argv(self.facts, self.layout, self.closure, ["true"],
                                         env={"WEBKIT_FORCE_SANDBOX": "1"})
        self.assertNotIn("WEBKIT_FORCE_SANDBOX", guest)

    def test_omitted_cwd_inherits_the_caller_directory(self):
        argv, _, _ = proot_command_argv(self.facts, self.layout, self.closure, ["true"], cwd=None)
        self.assertNotIn("-w", argv)

    def test_wrapper_script_forwards_arguments_and_quotes_every_word(self):
        text = wrapper_script(["/nix/store/x/bin/env", "A=b c", "it's"])
        self.assertTrue(text.startswith("#!/bin/sh\nexec "))
        self.assertTrue(text.endswith(' "$@"\n'))
        self.assertIn("'A=b c'", text)
        self.assertIn("'\"'\"'", text)


class GuestCase(unittest.TestCase):
    """A cooperative scripted guest: each recognised probe script gets the stdout a faithful guest would print."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name).resolve()
        (self.base / "proc").mkdir()
        self.facts = make_facts()
        self.closure = closure_for(self.facts)
        self.layout = prepare_layout(self.base / "guest", self.base / "cache")
        self.calls = []
        self.overrides = {}
        self.observations = {}
        self.ldd = {}
        self.rt = GuestRuntime(
            self.facts, self.layout, self.closure, prefix=["sudo", "-n", "unshare", "--net", "--"],
            env={"PATH": "/usr/bin", "LD_LIBRARY_PATH": "/usr/lib", "THEME_FORGE_CACHE_DIR": str(self.layout.cache_dir)},
            runner=self.runner, popen=self.popen, sleep=lambda seconds: None, proc_root=self.base / "proc",
            host_userns=lambda: "user:[4026531837]")

    def code_of(self, argv, marker):
        return next((a for a in argv if marker in a), None)

    def runner(self, argv, **kwargs):
        self.calls.append(argv)
        self.assertFalse([k for k in kwargs["env"] if k.startswith("LD_")], "host LD_* must not reach the host side")
        text = "\n".join(argv)
        for marker, produce in self.overrides.items():
            if marker in text:
                return produce(argv)
        if "rs9-translation-nonce" in text:
            nonce = (self.layout.tmp_dir / "rs9-translation-nonce").read_text()
            body = {"userns": "user:[4026531837]", "uid": os.getuid(), "nonce": nonce, "visible": [],
                    "etc": ["group", "hosts", "nsswitch.conf", "passwd"]}
            return completed(argv, 0, json.dumps(body).encode())
        if "readlink('/proc/self/exe')" in text:
            return completed(argv, 0, json.dumps({"exe": self.facts["python"]}).encode())
        if "readlinkSync" in text:
            return completed(argv, 0, json.dumps({"exe": self.facts["node"], "execPath": self.facts["node"]}).encode())
        if "rs9-observer.py" in text:
            label = re.search(r"rs9-observe-(\w+)\.json", argv[-1]).group(1)
            return completed(argv, 0, json.dumps(self.observations[label]).encode())
        if self.facts["ldd"] in argv:
            code, out = self.ldd.get(argv[-1], (0, self.resolved()))
            return completed(argv, code, out)
        code = self.code_of(argv, "sys.argv[1:]")
        if code:
            return completed(argv, 0, json.dumps(argv[argv.index(code) + 1:]).encode())
        code = self.code_of(argv, "sys.exit(")
        if code:
            return completed(argv, int(re.search(r"sys\.exit\((\d+)\)", code).group(1)))
        if "SIG_DFL" in text:
            return completed(argv, -signal.SIGTERM)
        if "time.sleep(600)" in text:
            return completed(argv, 0)
        if "connect_ex" in text:
            return completed(argv, 0, json.dumps({"connect_errno": errno.ENETUNREACH, "interfaces": ["lo"]}).encode())
        if self.facts["bwrap"] in argv:
            return completed(argv, 1, b"", b"bwrap: No permissions to create new namespace")
        return completed(argv, 0)

    def resolved(self):
        libc = self.facts["glibc_lib"] + "/libc.so.6"
        return (f"\tlinux-vdso.so.1 (0x00007ffd)\n\tlibc.so.6 => {libc} (0x00007f01)\n"
                f"\t{self.facts['foreign_interpreter']} (0x00007f02)\n").encode()

    def popen(self, argv, **kwargs):
        self.assertIs(kwargs.get("start_new_session"), True)
        layout = self.layout
        ready = re.search(r"/tmp/(rs9-ready-[0-9a-f]+)", self.code_of(argv, "rs9-ready-")).group(1)
        marker = re.search(r"/tmp/(rs9-term-[0-9a-f]+)", self.code_of(argv, "rs9-term-")).group(1)
        test = self

        class Wrapper:
            returncode = None
            signals = []
            group_signals = []

            def __init__(self):
                if not test.silent_guest:
                    (layout.tmp_dir / ready).write_text("1")

            def poll(self):
                return self.returncode

            def send_signal(self, number):
                self.signals.append(number)
                if test.term_handled:
                    (layout.tmp_dir / marker).write_text(str(int(number)))
                self.returncode = 0 if test.term_handled else -9

            def send_group_signal(self, number):
                self.group_signals.append(number)
                if test.term_handled or getattr(test, "group_term_handled", False):
                    (layout.tmp_dir / marker).write_text(str(int(number)))
                self.returncode = 0

            def wait(self, timeout=None):
                if test.hangs:
                    raise subprocess.TimeoutExpired(argv, timeout)
                return self.returncode

            def kill(self):
                self.returncode = -9

        return Wrapper()

    silent_guest = False
    term_handled = True
    group_term_handled = False
    hangs = False

    def proc(self, pid, ppid, comm, cls="expected", **extra):
        row = {"pid": pid, "ppid": ppid, "comm": comm, "exe_class": cls, "interps": 1, "interps_pinned": 1,
               "libcs": 1, "libcs_pinned": 1, "outside_system": 0, "outside_other": 0, "no_new_privs": 1, "seccomp": 2}
        row.update(extra)
        return row

    def observed(self, processes, root_pid=10, root_is_elf=True):
        return {"label": "x", "status": "observed", "root_is_elf": root_is_elf, "root_pid": root_pid,
                "early_exit_code": None, "processes": processes}


class TranslationProbeTests(GuestCase):
    def test_same_userns_inode_and_translated_paths_pass(self):
        row = probe_no_userns_ptrace(self.rt)
        self.assertEqual((row["name"], row["status"]), ("proot-no-userns-ptrace", "pass"))
        self.assertTrue(all(row["details"][k] for k in ("userns_inode_equal", "uid_equal", "tmp_translated",
                                                          "host_paths_hidden", "etc_closed")))
        self.assertIsInstance(self.rt.bind_count, int)
        self.assertNotIn("/", "".join(str(v) for v in row["details"].values() if isinstance(v, str)))

    def test_created_user_namespace_is_a_failure(self):
        self.rt.host_userns = lambda: "user:[1]"
        row = probe_no_userns_ptrace(self.rt)
        self.assertEqual((row["status"], row["reason"]), ("fail", "user-namespace-created"))

    def test_host_path_visibility_and_host_etc_are_failures(self):
        for field, value in (("visible", ["/etc/os-release"]), ("etc", ["passwd", "shadow"])):
            def leaky(argv, field=field, value=value):
                nonce = (self.layout.tmp_dir / "rs9-translation-nonce").read_text()
                body = {"userns": "user:[4026531837]", "uid": os.getuid(), "nonce": nonce, "visible": [],
                        "etc": ["passwd"], field: value}
                return completed(argv, 0, json.dumps(body).encode())
            self.overrides = {"rs9-translation-nonce": leaky}
            with self.subTest(field):
                row = probe_no_userns_ptrace(self.rt)
                self.assertEqual((row["status"], row["reason"]), ("fail", "path-translation-or-isolation-failed"))

    def test_ptrace_denial_is_classified_from_the_actual_stderr(self):
        self.overrides = {"rs9-translation-nonce": lambda a: completed(a, 1, b"", b"proot error: ptrace(TRACEME): Operation not permitted")}
        row = probe_no_userns_ptrace(self.rt)
        self.assertEqual((row["status"], row["reason"]), ("fail", "ptrace-denied"))
        self.assertEqual(len(row["details"]["stderr_sha256"]), 64)

    def test_timeout_is_recorded_separately_from_bind_count(self):
        def hang(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 1)
        self.rt.runner = hang
        row = probe_no_userns_ptrace(self.rt)
        self.assertEqual((row["status"], row["reason"]), ("fail", "probe-timeout"))
        self.assertEqual(self.rt.timeouts, {"proot-no-userns-ptrace": 1})
        self.assertIsInstance(self.rt.bind_count, int)


class SelfAndInterpreterProbeTests(GuestCase):
    def test_pinned_tools_released_sea_and_main_pass(self):
        obs = {"sea": self.observed([self.proc(10, 1, "sidecar")]),
               "main": self.observed([self.proc(10, 1, "launcher", "other"), self.proc(11, 10, "app")],
                                     root_is_elf=False)}
        row = probe_executable_self(self.rt, obs)
        self.assertEqual(row["status"], "pass", row)
        self.assertEqual(row["details"]["method"], "guest-sibling-procfs-readback")
        self.assertEqual(probe_descendant_interpreter(self.rt, obs)["status"], "pass")

    def test_loader_or_proot_as_executable_self_fails(self):
        for cls in ("loader", "proot"):
            obs = {"sea": self.observed([self.proc(10, 1, "sidecar", cls)]), "main": self.observed([self.proc(10, 1, "a")])}
            with self.subTest(cls):
                row = probe_executable_self(self.rt, obs)
                self.assertEqual((row["status"], row["reason"]), ("fail", "executable-self-diverged"))

    def test_root_elf_that_is_not_the_released_file_fails(self):
        obs = {"sea": self.observed([self.proc(10, 1, "sidecar", "other"), self.proc(11, 10, "x")]),
               "main": self.observed([self.proc(10, 1, "a")])}
        self.assertEqual(probe_executable_self(self.rt, obs)["reason"], "root-executable-self-diverged")

    def test_missing_or_unobserved_release_is_not_a_pass(self):
        main = self.observed([self.proc(10, 1, "a")])
        row = probe_executable_self(self.rt, {"sea": {"status": "not-run", "reason": "sea-executable-unresolved"}, "main": main})
        self.assertEqual((row["status"], row["reason"]), ("not-run", "sea-executable-unresolved"))
        row = probe_executable_self(self.rt, {"sea": {"status": "unobserved", "reason": "exited-before-observation"}, "main": main})
        self.assertEqual((row["status"], row["reason"]), ("fail", "exited-before-observation"))
        row = probe_executable_self(self.rt, {"main": main})
        self.assertEqual(row["status"], "not-run")
        row = probe_executable_self(self.rt, {"sea": self.observed([self.proc(10, 1, "o", "other")], root_is_elf=False),
                                              "main": main})
        self.assertEqual((row["status"], row["reason"]), ("fail", "no-released-process-observed"))

    def test_tool_self_divergence_is_detected(self):
        self.overrides = {"readlinkSync": lambda a: completed(a, 0, json.dumps(
            {"exe": self.facts["loader"], "execPath": self.facts["node"]}).encode())}
        obs = {"sea": self.observed([self.proc(10, 1, "s")]), "main": self.observed([self.proc(10, 1, "a")])}
        row = probe_executable_self(self.rt, obs)
        self.assertEqual((row["status"], row["reason"]), ("fail", "executable-self-diverged"))
        self.assertEqual(row["details"]["parts"]["tool-python"]["status"], "pass")

    def test_unpinned_interpreter_libc_and_host_maps_fail(self):
        for name, changes, reason in (
                ("interp", {"interps_pinned": 0}, "descendant-interpreter-or-libc-not-pinned"),
                ("libc", {"libcs_pinned": 0}, "descendant-interpreter-or-libc-not-pinned"),
                ("no-libc", {"libcs": 0, "libcs_pinned": 0}, "descendant-interpreter-or-libc-not-pinned"),
                ("host", {"outside_system": 2}, "host-library-mapped")):
            obs = {"sea": self.observed([self.proc(10, 1, "s", **changes)]), "main": self.observed([self.proc(10, 1, "a")])}
            with self.subTest(name):
                row = probe_descendant_interpreter(self.rt, obs)
                self.assertEqual((row["status"], row["reason"]), ("fail", reason))

    def test_host_library_in_any_descendant_fails_even_when_not_released(self):
        obs = {"sea": self.observed([self.proc(10, 1, "s")]),
               "main": self.observed([self.proc(10, 1, "a"), self.proc(11, 10, "helper", "other", outside_system=1)])}
        self.assertEqual(probe_descendant_interpreter(self.rt, obs)["reason"], "host-library-mapped")

    def test_outside_other_mappings_fail_descendant_interpreter_probe(self):
        obs = {"sea": self.observed([self.proc(10, 1, "s", outside_other=1)]),
               "main": self.observed([self.proc(10, 1, "a")])}
        row = probe_descendant_interpreter(self.rt, obs)
        self.assertEqual((row["status"], row["reason"]), ("fail", "outside-other-mapped"))
        self.assertEqual(row["details"]["parts"]["sea"]["outside_other_maps"], 1)

    def test_outside_other_in_any_descendant_fails(self):
        obs = {"sea": self.observed([self.proc(10, 1, "s")]),
               "main": self.observed([self.proc(10, 1, "a"), self.proc(11, 10, "helper", "other", outside_other=2)])}
        row = probe_descendant_interpreter(self.rt, obs)
        self.assertEqual((row["status"], row["reason"]), ("fail", "outside-other-mapped"))


class ObserverTests(GuestCase):
    def test_observer_runs_in_the_guest_with_a_closed_spec_and_no_display_by_default(self):
        self.observations["sea"] = {"started": True, "early_exit_code": None, "root_pid": 10,
                                    "processes": [self.proc(10, 1, "sidecar")]}
        obs = observe_native(self.rt, "/cache/sidecar", label="sea", expected=["/cache/sidecar"], root_is_elf=True)
        self.assertEqual(obs["status"], "observed")
        spec = json.loads((self.layout.tmp_dir / "rs9-observe-sea.json").read_text())
        self.assertEqual((spec["exe"], spec["expected"], spec["glibc_lib"]), ("/cache/sidecar", ["/cache/sidecar"],
                                                                           self.facts["glibc_lib"]))
        self.assertNotIn("/nix/store/", spec["allowed"])
        self.assertTrue(all(p + "/" in spec["allowed"] for p in self.closure))
        self.assertNotIn("/etc/", spec["allowed"])
        self.assertTrue((self.layout.tmp_dir / "rs9-observer.py").is_file())
        self.assertNotIn("xvfb-run", self.calls[-1])
        self.assertNotIn("dbus-run-session", self.calls[-1])

    def test_display_runs_use_the_same_xvfb_and_dbus_session_as_the_smoke(self):
        self.observations["main"] = {"started": True, "root_pid": 10, "processes": [self.proc(10, 1, "app")]}
        observe_native(self.rt, "/cache/launcher", label="main", expected=[], root_is_elf=False, display=True,
                       until_webkit=True)
        tail = self.calls[-1][self.calls[-1].index("xvfb-run"):]
        self.assertEqual(tail[:4], ["xvfb-run", "-a", "dbus-run-session", "--"])

    def test_early_exit_before_any_readable_exe_is_unobserved_not_passed(self):
        self.observations["sea"] = {"started": True, "early_exit_code": 1, "root_pid": 10,
                                    "processes": [self.proc(10, 1, "sidecar", "unreadable")]}
        obs = observe_native(self.rt, "/c/s", label="sea", expected=[], root_is_elf=True)
        self.assertEqual((obs["status"], obs["reason"]), ("unobserved", "exited-before-observation"))

    def test_spawn_failure_and_guest_failure_are_unobserved(self):
        self.observations["sea"] = {"started": False, "processes": []}
        self.assertEqual(observe_native(self.rt, "/c/s", label="sea", expected=[], root_is_elf=True)["reason"],
                         "release-process-not-started")
        self.overrides = {"rs9-observer.py": lambda a: completed(a, 1, b"", b"proot warning: ptrace denied")}
        self.assertEqual(observe_native(self.rt, "/c/s", label="sea", expected=[], root_is_elf=True)["reason"],
                         "ptrace-denied")

    def test_observer_script_is_valid_python(self):
        from rs9.nix_proot import _OBSERVER
        compile(_OBSERVER, "observer", "exec")

    def test_observer_mapping_classification_excludes_memfd_and_anon(self):
        spec = {"glibc_lib": "/nix/store/glibc/lib", "allowed": ["/nix/store/glibc/"]}
        maps_lines = [
            "7f000-7f100 r-xp 00000 00:00 0 /memfd:wayland-shm (deleted)",
            "7f100-7f200 rw-p 00000 00:00 0 //anon (deleted)",
            "7f200-7f300 rw-p 00000 00:00 0 /[aio]",
            "7f300-7f400 rw-s 00000 00:00 0 /SYSV00000000 (deleted)",
            "7f400-7f500 r-xp 00000 00:00 0 /opt/host/libfoo.so",
        ]
        import ast
        from types import SimpleNamespace
        from rs9.nix_proot import _OBSERVER
        nodes = [n for n in ast.parse(_OBSERVER).body
                 if isinstance(n, ast.FunctionDef) and n.name in {"describe", "is_loader"}]
        namespace = {"spec": spec, "PROC": "/proc", "expected": set(),
                     "os": SimpleNamespace(path=os.path, readlink=lambda path: "/nix/store/glibc/bin/python"),
                     "text": lambda path: "\n".join(maps_lines) if path.endswith("/maps") else ""}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "observer-functions", "exec"), namespace)
        out = namespace["describe"](10, {"ppid": 1, "comm": "python"})
        self.assertEqual(out["outside_system"], 0)
        self.assertEqual(out["outside_other"], 1)


class ClosureProbeTests(GuestCase):
    def test_resolved_static_and_measured_closure_pass(self):
        self.ldd["/c/static"] = (1, b"\tnot a dynamic executable\n")
        row = probe_closure_resolution(self.rt, ["/c/a", "/c/static"], 123456)
        self.assertEqual(row["status"], "pass", row)
        self.assertEqual((row["details"]["resolved_count"], row["details"]["static_count"]), (1, 1))
        self.assertEqual(row["details"]["closure_size_bytes"], 123456)
        self.assertEqual(row["details"]["closure_path_count"], len(self.closure))

    def test_missing_and_foreign_resolution_fail(self):
        for name, result, key in (("missing", (0, b"\tlibgtk-3.so.0 => not found\n"), "missing"),
                                  ("host", (0, b"\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1)\n"), "outside-closure"),
                                  ("unlisted", (0, b"\tlibc.so.6 => " + store("elsewhere").encode() + b"/lib/libc.so.6 (0x1)\n"), "outside-closure"),
                                  ("failed", (127, b""), "ldd-failed")):
            self.ldd["/c/a"] = result
            with self.subTest(name):
                row = probe_closure_resolution(self.rt, ["/c/a"], 10)
                self.assertEqual((row["status"], row["reason"]), ("fail", "unresolved-closure-dependencies"))
                self.assertEqual(row["details"]["problems"][key], 1)

    def test_absolute_dt_needed_and_foreign_interpreter_lines_fail_when_outside_closure(self):
        cases = {
            "absolute-dt-needed-host": (0, b"\t/usr/lib64/libextra.so (0x00007f01)\n"),
            "absolute-dt-needed-unlisted": (0, b"\t" + store("elsewhere").encode() + b"/lib/libextra.so (0x00007f01)\n"),
            "unpinned-interpreter": (0, b"\t/lib/x86_64-linux-gnu/ld-2.31.so (0x00007f02)\n"),
            "wrong-arch-interpreter": (0, b"\t/lib/ld-linux-aarch64.so.1 (0x00007f02)\n"),
        }
        for name, result in cases.items():
            self.ldd["/c/a"] = result
            with self.subTest(name):
                row = probe_closure_resolution(self.rt, ["/c/a"], 10)
                self.assertEqual((row["status"], row["reason"]), ("fail", "unresolved-closure-dependencies"))
                self.assertEqual(row["details"]["problems"]["outside-closure"], 1)

    def test_absolute_dt_needed_inside_closure_and_pinned_interpreter_pass(self):
        inside_lib = self.closure[0] + "/lib/libextra.so"
        out = (f"\tlinux-vdso.so.1 (0x00007ffd)\n\t{inside_lib} (0x00007f01)\n"
               f"\t{self.facts['foreign_interpreter']} (0x00007f02)\n").encode()
        self.ldd["/c/a"] = (0, out)
        row = probe_closure_resolution(self.rt, ["/c/a"], 10)
        self.assertEqual(row["status"], "pass")
        self.assertEqual(row["details"]["resolved_count"], 1)

    def test_missing_inventory_or_size_never_passes(self):
        self.assertEqual(probe_closure_resolution(self.rt, None, 10)["status"], "not-run")
        self.assertEqual(probe_closure_resolution(self.rt, [], 10)["reason"], "no-released-elf-inventory")
        for size in (None, 0, -1, "10"):
            self.assertEqual(probe_closure_resolution(self.rt, ["/c/a"], size)["reason"], "closure-size-unmeasured")
        self.assertEqual(probe_closure_resolution(self.rt, [f"/c/{i}" for i in range(513)], 10)["reason"],
                         "elf-inventory-bound-exceeded")

    def test_timeouts_and_budget_are_failures_counted_separately(self):
        def hang(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 1)
        self.rt.runner = hang
        row = probe_closure_resolution(self.rt, ["/c/a"], 10)
        self.assertEqual(row["details"]["problems"]["timeout"], 1)
        self.assertEqual(self.rt.timeouts, {"proot-closure-resolution": 1})
        self.rt.runner = self.runner
        self.assertEqual(probe_closure_resolution(self.rt, ["/c/a", "/c/b"], 10, budget_seconds=-1)["reason"],
                         "closure-budget-exhausted")


class ArgsExitSignalTests(GuestCase):
    def test_arguments_exit_codes_signals_and_orphans_pass(self):
        row = probe_args_exit_signals_orphans(self.rt)
        self.assertEqual(row["status"], "pass", row)
        self.assertEqual(row["details"]["exit_codes_verified"], [0, 7, 42])
        self.assertEqual(row["details"]["guest_signal_exit_code"], -signal.SIGTERM)
        self.assertEqual(row["details"]["orphaned_tracees"], 0)
        self.assertTrue(row["details"]["external_sigterm"]["guest_handler_observed"])

    def test_argument_corruption_is_detected(self):
        self.overrides = {"sys.argv[1:]": lambda a: completed(a, 0, b'["arg"]')}
        self.assertEqual(probe_args_exit_signals_orphans(self.rt)["reason"], "argument-forwarding-mismatch")

    def test_exit_status_not_forwarded_is_detected(self):
        self.overrides = {"sys.exit(7)": lambda a: completed(a, 0)}
        row = probe_args_exit_signals_orphans(self.rt)
        self.assertEqual((row["reason"], row["details"]["expected_exit"]), ("exit-code-propagation-failed", 7))

    def test_guest_signal_death_must_be_reflected(self):
        self.overrides = {"SIG_DFL": lambda a: completed(a, 255)}
        self.assertEqual(probe_args_exit_signals_orphans(self.rt)["reason"], "guest-signal-status-not-propagated")
        self.overrides = {"SIG_DFL": lambda a: completed(a, 128 + signal.SIGTERM)}
        self.assertEqual(probe_args_exit_signals_orphans(self.rt)["status"], "pass")

    def test_surviving_orphan_is_reported_and_killed(self):
        def orphaning(argv):
            token = argv[-1]
            (self.base / "proc" / "4242").mkdir()
            (self.base / "proc" / "4242" / "cmdline").write_bytes(b"python\0-c\0sleep\0" + token.encode() + b"\0")
            return completed(argv, 0)
        self.overrides = {"time.sleep(600)": orphaning}
        with patch("rs9.nix_proot.os.kill") as kill:
            row = probe_args_exit_signals_orphans(self.rt)
        self.assertEqual((row["status"], row["reason"]), ("fail", "orphaned-tracee-survived"))
        self.assertEqual(row["details"]["orphaned_tracees"], 1)
        kill.assert_called_once_with(4242, signal.SIGKILL)

    def test_external_sigterm_that_never_stops_the_wrapper_fails(self):
        self.hangs = True
        row = probe_args_exit_signals_orphans(self.rt)
        self.assertEqual((row["status"], row["reason"]), ("fail", "sigterm-did-not-terminate-wrapper"))
        self.assertEqual(self.rt.timeouts, {"proot-args-exit-signals": 2})

    def test_guest_that_never_becomes_ready_fails_instead_of_passing(self):
        self.silent_guest = True
        row = probe_args_exit_signals_orphans(self.rt)
        self.assertEqual((row["status"], row["reason"]), ("fail", "signal-probe-guest-not-ready"))

    def test_unhandled_term_is_recorded_not_assumed(self):
        self.term_handled = False
        row = probe_args_exit_signals_orphans(self.rt)
        self.assertEqual(row["status"], "fail")
        self.assertEqual(row["reason"], "guest-sigterm-not-observed")
        self.assertFalse(row["details"]["guest_handler_observed"])

    def test_signal_attribution_and_product_wrapper_implication(self):
        row = probe_args_exit_signals_orphans(self.rt)
        self.assertEqual(row["status"], "pass")
        sig = row["details"]["external_sigterm"]
        self.assertEqual(sig["signal_target"], "sudo")
        self.assertEqual(sig["delivery_scope"], "outer-process")
        self.assertIn("outer process reached the guest handler", sig["product_wrapper_implication"])

    def test_wrapper_signal_failure_with_passing_process_group_control_remains_fail_closed(self):
        self.term_handled = False
        self.group_term_handled = True
        row = probe_args_exit_signals_orphans(self.rt)
        self.assertEqual(row["status"], "fail")
        self.assertEqual(row["reason"], "guest-sigterm-not-observed")
        sig = row["details"]
        self.assertFalse(sig["guest_handler_observed"])
        self.assertEqual(sig["signal_target"], "sudo")
        self.assertEqual(sig["delivery_scope"], "outer-process")
        self.assertIn("process_group_control", sig)
        ctrl = sig["process_group_control"]
        self.assertTrue(ctrl["guest_handler_observed"])
        self.assertEqual(ctrl["delivery_scope"], "process-group")
        self.assertEqual(ctrl["status"], "pass")
        self.assertIn("Outer-process delivery did not reach the guest handler", sig["product_wrapper_implication"])

    def test_unavailable_process_group_control_never_falls_back_to_outer_delivery(self):
        from types import SimpleNamespace
        self.term_handled = False
        calls = []
        def without_group(argv, **kwargs):
            wrapper = self.popen(argv, **kwargs)
            def deliver(number):
                calls.append(number); wrapper.send_signal(number)
            return SimpleNamespace(poll=wrapper.poll, wait=wrapper.wait, kill=wrapper.kill,
                                   send_signal=deliver)
        self.rt.popen = without_group
        row = probe_args_exit_signals_orphans(self.rt)
        self.assertEqual(row["reason"], "guest-sigterm-not-observed")
        control = row["details"]["process_group_control"]
        self.assertEqual((control["status"], control["reason"]),
                         ("fail", "process-group-delivery-unavailable"))
        self.assertEqual(calls, [signal.SIGTERM])


class OfflineProbeTests(GuestCase):
    def test_pass_comes_only_from_the_explicit_in_guest_denial(self):
        row = probe_in_guest_offline(self.rt)
        self.assertEqual((row["status"], row["runtime_offline_status"]), ("pass", "pass"))
        self.assertEqual((row["details"]["connect_errno"], row["details"]["denied"], row["details"]["loopback_only"]),
                         (errno.ENETUNREACH, True, True))

    def test_no_netns_prefix_is_not_run_not_pass(self):
        self.rt.prefix = []
        row = probe_in_guest_offline(self.rt)
        self.assertEqual((row["status"], row["runtime_offline_status"]), ("not-run", "not-run"))
        self.assertEqual(self.calls, [])

    def test_reachable_network_extra_interface_or_unparseable_output_fail(self):
        for body in ({"connect_errno": 0, "interfaces": ["lo"]}, {"connect_errno": 111, "interfaces": ["lo"]},
                     {"connect_errno": errno.ENETUNREACH, "interfaces": ["lo", "eth0"]}):
            self.overrides = {"connect_ex": lambda a, body=body: completed(a, 0, json.dumps(body).encode())}
            with self.subTest(body):
                row = probe_in_guest_offline(self.rt)
                self.assertEqual((row["status"], row["runtime_offline_status"]), ("fail", "fail"))
        self.overrides = {"connect_ex": lambda a: completed(a, 0, b"offline-verified")}
        row = probe_in_guest_offline(self.rt)
        self.assertEqual((row["status"], row["runtime_offline_status"], row["reason"]),
                         ("fail", "fail", "offline-probe-unparseable"))


class WebkitProbeTests(GuestCase):
    def main(self, *extra):
        return self.observed([self.proc(10, 1, "launcher", "other"), self.proc(11, 10, "app"), *extra], root_is_elf=False)

    def test_web_process_under_bwrap_passes_and_records_flags(self):
        main = self.main(self.proc(12, 11, "bwrap", "other"),
                         self.proc(13, 12, "WebKitWebProces", "other", no_new_privs=1, seccomp=2))
        row = probe_webkit_sandbox_state(self.rt, main)
        self.assertEqual(row["status"], "pass", row)
        self.assertEqual(row["details"]["sandboxed_web_processes"], 1)
        self.assertIs(row["details"]["sandbox_disabled_by_experiment"], False)

    def test_unsandboxed_web_process_fails_without_the_experiment_disabling_anything(self):
        row = probe_webkit_sandbox_state(self.rt, self.main(self.proc(13, 11, "WebKitWebProces", "other")))
        self.assertEqual((row["status"], row["reason"]), ("fail", "webkit-sandbox-not-observed-enabled"))
        self.assertIs(row["details"]["sandbox_disabled_by_experiment"], False)

    def test_no_web_process_is_a_failure_with_the_bwrap_mechanism_recorded(self):
        mechanism = {"exit_code": 1, "diagnostic_token": "userns-denied"}
        row = probe_webkit_sandbox_state(self.rt, self.main(self.proc(12, 11, "bwrap", "other")), mechanism)
        self.assertEqual((row["status"], row["reason"]), ("fail", "webkit-web-process-not-observed"))
        self.assertEqual(row["details"]["bwrap_mechanism"], mechanism)

    def test_unobserved_main_fails_and_absent_main_is_not_run(self):
        self.assertEqual(probe_webkit_sandbox_state(self.rt, {"status": "unobserved", "reason": "x"})["status"], "fail")
        self.assertEqual(probe_webkit_sandbox_state(self.rt, None)["status"], "not-run")
        self.assertEqual(probe_webkit_sandbox_state(self.rt, {"status": "not-run", "reason": "launcher-unresolved"})["reason"],
                         "launcher-unresolved")

    def test_confounded_baseline_diagnostics_are_recorded_and_labeled(self):
        main = self.main(self.proc(12, 11, "bwrap", "other"),
                         self.proc(13, 12, "WebKitWebProces", "other", no_new_privs=1, seccomp=2))
        row = probe_webkit_sandbox_state(self.rt, main)
        self.assertEqual(row["status"], "pass")
        details = row["details"]
        self.assertEqual(details["baseline_no_new_privs"], 1)
        self.assertEqual(details["baseline_seccomp"], 2)
        self.assertTrue(details["sandbox_diagnostics_confounded"])
        self.assertTrue(details["nnp_seccomp_confounded"])

    def test_unsandboxed_web_process_fails_even_with_confounded_baseline(self):
        main = self.main(self.proc(13, 11, "WebKitWebProces", "other", no_new_privs=1, seccomp=2))
        row = probe_webkit_sandbox_state(self.rt, main)
        self.assertEqual((row["status"], row["reason"]), ("fail", "webkit-sandbox-not-observed-enabled"))
        self.assertTrue(row["details"]["sandbox_diagnostics_confounded"])

    def test_different_baseline_does_not_make_seccomp_independent_sandbox_evidence(self):
        baseline_launcher = self.proc(10, 1, "launcher", "other", no_new_privs=0, seccomp=0)
        app = self.proc(11, 10, "app", no_new_privs=0, seccomp=0)
        bwrap = self.proc(12, 11, "bwrap", "other")
        web = self.proc(13, 12, "WebKitWebProces", "other", no_new_privs=0, seccomp=0)
        main = self.observed([baseline_launcher, app, bwrap, web], root_is_elf=False)
        row = probe_webkit_sandbox_state(self.rt, main)
        self.assertTrue(row["details"]["sandbox_diagnostics_confounded"])
        self.assertFalse(row["details"]["baseline_matches_proot_acceleration"])
        self.assertEqual((row["status"], row["reason"]), ("fail", "webkit-sandbox-not-observed-enabled"))


class SmokeProbeTests(unittest.TestCase):
    def test_absent_inputs_are_not_run(self):
        self.assertEqual(probe_verifier_and_smoke(None)["status"], "not-run")

    def test_contract_failure_and_incomplete_evidence_fail(self):
        def broken():
            raise ContractError("SIDECAR_VERIFIER", "rejected", details={"reason": "runtime-identity", "exit_code": 2})
        row = probe_verifier_and_smoke(broken)
        self.assertEqual((row["status"], row["reason"]), ("fail", "SIDECAR_VERIFIER"))
        self.assertEqual(row["details"]["exit_code"], 2)
        self.assertEqual(probe_verifier_and_smoke(lambda: {})["reason"], "verifier-smoke-evidence-incomplete")
        self.assertEqual(probe_verifier_and_smoke(lambda: {"sidecar": {"verified": True}, "scenarios": []})["status"], "fail")
        self.assertEqual(probe_verifier_and_smoke(lambda: (_ for _ in ()).throw(OSError()))["reason"],
                         "verifier-smoke-execution-failed")

    def test_released_evidence_passes(self):
        row = probe_verifier_and_smoke(lambda: {"sidecar": {"verified": True}, "scenarios": [{"scenario": "C"}],
                                                "drift": {"has_drift": False}})
        self.assertEqual((row["status"], row["details"]["scenarios"], row["details"]["drift"]), ("pass", ["C"], False))


class EvaluationTests(GuestCase):
    recipe = f'{{ version = "{PROOT_VERSION}"; hash = "{PROOT_SOURCE_HASH}"; }}\n'.encode()

    def released_observations(self):
        sea = [self.proc(10, 1, "sidecar")]
        main = [self.proc(10, 1, "launcher", "other"), self.proc(11, 10, "app"),
                self.proc(12, 11, "bwrap", "other"), self.proc(13, 12, "WebKitWebProces", "other")]
        self.observations["sea"] = {"started": True, "early_exit_code": None, "root_pid": 10, "processes": sea}
        self.observations["main"] = {"started": True, "early_exit_code": None, "root_pid": 10, "processes": main}

    def test_missing_evidence_is_never_a_pass(self):
        result = evaluate_proot_experiment(self.rt, None)
        self.assertEqual(result["schema"], SCHEMA)
        self.assertIs(result["application_qualified"], False)
        self.assertIs(result["qualification_authority"], False)
        self.assertEqual(result["status"], "diagnostic-fail")
        statuses = {g["name"]: g["status"] for g in result["gates"]}
        self.assertEqual(list(statuses), list(GATES))
        self.assertEqual(statuses, {
            "proot-pinned-derivation": "not-run", "proot-no-userns-ptrace": "pass", "proot-executable-self": "not-run",
            "proot-descendant-interpreter": "not-run", "proot-closure-resolution": "not-run",
            "proot-args-exit-signals": "pass", "proot-in-guest-offline": "pass", "proot-webkit-sandbox-state": "not-run",
            "proot-verifier-smoke": "not-run"})
        self.assertEqual({g["name"] for g in result["gaps"]}, {n for n, s in statuses.items() if s != "pass"})

    def test_failed_release_materialization_fails_dependent_gates_with_its_code(self):
        def broken():
            raise ContractError("NIX_COMMAND", "Installed PRoot command contract failed")
        result = evaluate_proot_experiment(self.rt, None, materialize=broken, closure_size_bytes=5)
        gates = {g["name"]: g for g in result["gates"]}
        self.assertEqual(gates["proot-verifier-smoke"]["reason"], "NIX_COMMAND")
        self.assertEqual(gates["proot-executable-self"]["status"], "fail")
        self.assertEqual(gates["proot-closure-resolution"]["reason"], "no-released-elf-inventory")
        self.assertEqual(gates["proot-webkit-sandbox-state"]["status"], "fail")
        self.assertEqual(result["status"], "diagnostic-fail")

    def test_unexpected_materialization_error_is_a_failure_not_an_exception(self):
        def broken():
            raise OSError("disk")
        result = evaluate_proot_experiment(self.rt, None, materialize=broken)
        gates = {g["name"]: g for g in result["gates"]}
        self.assertEqual(gates["proot-verifier-smoke"]["reason"], "release-materialization-failed")

    def test_unresolved_sea_and_launcher_are_not_run_and_smoke_still_runs(self):
        released = {"elfs": ["/c/a"], "sea": None, "launcher": None, "launcher_is_elf": False}
        seen = []
        result = evaluate_proot_experiment(self.rt, None, materialize=lambda: released, closure_size_bytes=9,
                                           smoke=lambda r: seen.append(r) or {"sidecar": {"verified": True},
                                                                              "scenarios": [{"scenario": "C"}]})
        gates = {g["name"]: g for g in result["gates"]}
        self.assertEqual(gates["proot-executable-self"]["reason"], "sea-executable-unresolved")
        self.assertEqual(gates["proot-webkit-sandbox-state"]["reason"], "launcher-unresolved")
        self.assertEqual(gates["proot-verifier-smoke"]["status"], "pass")
        self.assertEqual(gates["proot-closure-resolution"]["status"], "pass")
        self.assertEqual(seen, [released])

    def test_smoke_runs_before_the_observers_relaunch_the_release(self):
        self.released_observations()
        order = []
        released = {"elfs": ["/c/a"], "sea": "/c/sidecar", "launcher": "/c/launch", "launcher_is_elf": False}
        self.rt.runner = lambda argv, **kw: (order.append("observer" if "rs9-observer.py" in "\n".join(argv) else "other"),
                                              self.runner(argv, **kw))[1]
        evaluate_proot_experiment(self.rt, None, materialize=lambda: released,
                                  smoke=lambda r: order.append("smoke") or {"sidecar": {"verified": True},
                                                                            "scenarios": [{"scenario": "C"}]})
        self.assertLess(order.index("smoke"), order.index("observer"))

    def test_fully_observed_release_passes_every_gate_and_stays_unqualified(self):
        self.released_observations()
        released = {"elfs": ["/c/a", "/c/b"], "sea": "/c/sidecar", "launcher": "/c/launch", "launcher_is_elf": False}
        blob = hashlib.sha1(b"blob %d\0" % len(self.recipe) + self.recipe).hexdigest()
        self.facts["proot_recipe_blob"] = blob
        with patch("rs9.nix_proot.PROOT_RECIPE_BLOB", blob):
            result = evaluate_proot_experiment(
                self.rt, self.recipe, materialize=lambda: released, closure_size_bytes=4096,
                smoke=lambda r: {"sidecar": {"verified": True}, "scenarios": [{"scenario": "C"}, {"scenario": "C-signal"}]})
        failed = [p for p in result["probes"] if p["status"] != "pass"]
        # The scripted bwrap mechanism is denied, but the observed descendant tree is what gates the sandbox.
        self.assertEqual(failed, [], failed)
        self.assertEqual(result["status"], "diagnostic-pass")
        self.assertEqual([g["name"] for g in result["gates"]], list(GATES))
        self.assertIs(result["application_qualified"], False)
        self.assertIs(result["qualification_authority"], False)
        offline = next(g for g in result["gates"] if g["name"] == "proot-in-guest-offline")
        self.assertEqual(offline["runtime_offline_status"], "pass")
        measured = result["measurements"]
        self.assertEqual((measured["closure_size_bytes"], measured["closure_path_count"], measured["timeouts"]),
                         (4096, len(self.closure), {}))
        self.assertIsInstance(measured["bind_count"], int)
        self.assertGreater(measured["bind_count"], len(self.closure))
        self.assertEqual(result["gaps"], [])
        self.assertIsNone(result["reason"])
        text = json.dumps(result)
        self.assertNotIn(str(self.base), text)
        self.assertNotIn("/home/", text)


class BoundedExecutionTests(unittest.TestCase):
    def test_output_capacity_and_timeout_terminate_the_child(self):
        import sys
        from rs9.nix_proot import bounded_guest_run
        with patch("rs9.nix_proot.MAX_OUTPUT", 256):
            result = bounded_guest_run([sys.executable, "-c", "import sys,time;sys.stdout.write('x'*4096);sys.stdout.flush();time.sleep(60)"], env=dict(os.environ), timeout=3)
            self.assertEqual(len(result.stdout), 257)
        with self.assertRaises(subprocess.TimeoutExpired):
            bounded_guest_run([sys.executable, "-c", "import time;time.sleep(60)"], env=dict(os.environ), timeout=0.1)


if __name__ == "__main__":
    unittest.main()
