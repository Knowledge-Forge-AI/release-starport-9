"""Pure post-authentication EGL logging checks; no GUI or privileged commands."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.errors import ContractError
from rs9.hosted_commands import linux_runtime_prefix, runtime_environment
from rs9.hosted_nix import _nix_application_environment
from rs9 import hosted_smoke as smoke

FIXED = {"EGL_LOG_LEVEL": "debug", "LIBGL_DEBUG": "verbose"}


class CurrentNixEglDiagnosticsTests(unittest.TestCase):
    def prepared(self):
        return {"source_generation": CURRENT_GENERATION, "capture": {}, "fixture_capture": {}}

    def environment(self):
        return {"PATH": str(Path(sys.executable).parent), "DISPLAY": ":fixture",
                "WEBKIT_DISABLE_COMPOSITING_MODE": "1",
                "WEBKIT_DISABLE_DMABUF_RENDERER": "1"}

    def prefix(self, env):
        with patch("rs9.hosted_commands.os.getuid", return_value=1001), patch(
                "rs9.hosted_commands.os.getgid", return_value=1001):
            return linux_runtime_prefix(env)

    def transform(self, prefix, env, prepared, system, flag):
        with patch("rs9.hosted_commands.os.getuid", return_value=1001), patch(
                "rs9.hosted_commands.os.getgid", return_value=1001):
            return smoke._application_smoke_environment(
                prefix, env, prepared, system, current_linux_nix_egl_debug=flag)

    def test_shared_nix_environment_never_enables_debug_for_other_commands(self):
        source = dict(self.environment(), EGL_LOG_LEVEL="hostile", LIBGL_DEBUG="hostile")
        for generation in (CURRENT_GENERATION, HISTORICAL_GENERATION):
            for system in ("x86_64-linux", "aarch64-linux", "aarch64-darwin"):
                with self.subTest(generation=generation, system=system):
                    observed = _nix_application_environment(source, generation, system)
                    for name in FIXED:
                        self.assertNotIn(name, observed)
                        self.assertNotIn(name + "=", " ".join(self.prefix(observed)))

    def test_nix_caller_preserves_the_existing_direct_fixture_route(self):
        from rs9 import hosted_nix
        env = self.environment()
        for prefix in ([], self.prefix(env)):
            with patch.object(hosted_nix, "_pinned_session_bus_argv", return_value=["fixture"]), \
                 patch.object(hosted_nix, "verify_nebular_runtime", return_value={}) as verify:
                hosted_nix._verify_final_nebular_runtime(
                    "runtime", self.prepared(), "aarch64-linux", prefix, [], env,
                    None, {}, CURRENT_GENERATION)
            self.assertIs(verify.call_args.kwargs["current_linux_nix_egl_debug"], bool(prefix))
            self.assertEqual(verify.call_args.args[3], prefix)

    def test_shared_helpers_require_literal_true_and_override_hostile_values(self):
        source = dict(self.environment(), EGL_LOG_LEVEL="hostile", LIBGL_DEBUG="hostile")
        before = dict(source)
        neutral = runtime_environment(source)
        for flag in (False, None, 0, 1, "true", [], {}):
            with self.subTest(flag=flag):
                self.assertEqual(runtime_environment(
                    source, current_linux_nix_egl_debug=flag), neutral)
        self.assertEqual(runtime_environment(
            source, current_linux_nix_egl_debug=True), dict(neutral, **FIXED))
        self.assertEqual(source, before)

    def test_only_authenticated_current_linux_application_opts_in(self):
        env = self.environment()
        prefix = self.prefix(env) + ["/fixture/bin/rs9-nebular-fhs"]
        bad_prepared = [None, {}, {"source_generation": CURRENT_GENERATION},
                        dict(self.prepared(), source_generation=HISTORICAL_GENERATION),
                        dict(self.prepared(), capture=None),
                        dict(self.prepared(), fixture_capture=None)]
        for prepared in bad_prepared:
            with self.subTest(prepared=prepared):
                actual_prefix, actual_env = self.transform(
                    prefix, env, prepared, "x86_64-linux", True)
                self.assertIs(actual_prefix, prefix)
                self.assertIs(actual_env, env)
        for system in ("aarch64-darwin", "unsupported"):
            self.assertEqual(self.transform(
                prefix, env, self.prepared(), system, True), (prefix, env))
        for flag in (False, None, 0, 1, "true", [], {}):
            self.assertEqual(self.transform(
                prefix, env, self.prepared(), "aarch64-linux", flag), (prefix, env))
        for system in ("x86_64-linux", "aarch64-linux"):
            actual_prefix, actual_env = self.transform(
                prefix, env, self.prepared(), system, True)
            self.assertEqual(actual_env, dict(env, **FIXED))
            self.assertEqual(actual_prefix[:10], prefix[:10])
            self.assertEqual(actual_prefix[-1], prefix[-1])
            self.assertEqual(actual_prefix.count("EGL_LOG_LEVEL=debug"), 1)
            self.assertEqual(actual_prefix.count("LIBGL_DEBUG=verbose"), 1)
        self.assertEqual(env, self.environment())

    def test_generic_prefixes_are_preserved_without_argument_rewriting(self):
        env = self.environment()
        for prefix in (["wrapper", "EGL_LOG_LEVEL=argument", "LIBGL_DEBUG=argument"],
                       ("wrapper", "-i", "EGL_LOG_LEVEL=argument"), [], ()):
            observed_prefix, observed_env = self.transform(
                prefix, env, {}, "x86_64-linux", True)
            self.assertIs(observed_prefix, prefix)
            self.assertIs(observed_env, env)

    def test_application_opt_in_requires_existing_canonical_privilege_prefix(self):
        env = self.environment()
        for prefix in ([], ["wrapper", "-i"], ["sudo", "-n", "unshare", "--net"]):
            with self.subTest(prefix=prefix), self.assertRaises(ContractError) as caught:
                self.transform(prefix, env, self.prepared(), "x86_64-linux", True)
            self.assertEqual(caught.exception.code, "APPLICATION_SMOKE")

    def test_actual_restoration_tail_contains_only_fixed_new_values(self):
        env = self.environment()
        prefix = self.prefix(env)
        for flag in (False, True):
            actual, _ = self.transform(
                prefix, env, self.prepared(), "x86_64-linux", flag)
            result = subprocess.run(
                [*actual[10:], sys.executable, "-I", "-B", "-c",
                 "import json,os;print(json.dumps(dict(os.environ)))"],
                env={"ACTIONS_RUNTIME_TOKEN": "fixture-token"},
                capture_output=True, text=True, timeout=10, check=True)
            observed = json.loads(result.stdout)
            for name, value in FIXED.items():
                if flag:
                    self.assertEqual(observed[name], value)
                else:
                    self.assertNotIn(name, observed)
            self.assertNotIn("ACTIONS_RUNTIME_TOKEN", observed)

    def test_root_identity_remains_rejected(self):
        for uid, gid in ((0, 1001), (1001, 0), (0, 0)):
            for flag in (False, True):
                with patch("rs9.hosted_commands.os.getuid", return_value=uid), patch(
                        "rs9.hosted_commands.os.getgid", return_value=gid):
                    with self.assertRaises(ContractError) as caught:
                        linux_runtime_prefix(
                            self.environment(), current_linux_nix_egl_debug=flag)
                self.assertEqual(caught.exception.code, "UNPRIVILEGED_CLIENT_REQUIRED")

    def test_transform_is_invoked_after_existing_verifier_checks(self):
        events = []
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp).resolve()
            root, tools = work / "runtime", work / "smoke"
            (root / "bin").mkdir(parents=True)
            (root / "bin/tfsb-studio-service").write_bytes(b"fixture")
            (root / "lib/sidecar-payload").mkdir(parents=True)
            (root / "lib/sidecar-payload/manifest.json").write_text("[]")
            tools.mkdir()
            (tools / "native-rc-smoke.mjs").write_text("// fixture\n")
            (tools / "sidecar-common.mjs").write_text("// fixture\n")
            prepared = {"scratch": tools, "tools": tools, "source": tools, "records": []}
            env = dict(self.environment(), **FIXED)

            def imported(*args):
                events.append("import")
                self.assertTrue(all(name not in args[3] for name in FIXED))
                return {"status": "pass"}

            def verified(*args, **kwargs):
                events.append("verifier")
                self.assertTrue(all(name not in args[4] for name in FIXED))
                return {"status": "pass"}, {"status": "pass"}

            def transformed(prefix, child_env, passed_prepared, system, **kwargs):
                events.append("transform")
                self.assertIs(passed_prepared, prepared)
                self.assertIs(kwargs["current_linux_nix_egl_debug"], True)
                self.assertTrue(all(name not in child_env for name in FIXED))
                return prefix, child_env

            def application(**kwargs):
                events.append("application")
                return [{"scenario": "C"}]

            with patch.object(smoke, "verifier_import_preflight", side_effect=imported), \
                 patch.object(smoke, "_run_verifier", side_effect=verified), \
                 patch.object(smoke, "_application_smoke_environment", side_effect=transformed), \
                 patch("rs9.application_smoke_diagnostic.execute_application_smoke",
                       side_effect=application):
                smoke.verify_nebular_runtime(
                    root, prepared, "x86_64-linux", env=env,
                    current_linux_nix_egl_debug=True)
        self.assertEqual(events, ["import", "verifier", "transform", "application"])


if __name__ == "__main__":
    unittest.main()
