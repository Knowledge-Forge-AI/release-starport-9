"""Pure environment/argv checks; no GUI, namespace or native Nix execution."""
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.hosted_commands import linux_runtime_prefix, runtime_environment
from rs9.hosted_nix import _nix_application_environment


FLAGS = ("WEBKIT_DISABLE_COMPOSITING_MODE", "WEBKIT_DISABLE_DMABUF_RENDERER")


class CurrentNixHeadlessEnvironmentTests(unittest.TestCase):
    def test_current_linux_uses_fixed_flags_without_credentials_or_caller_override(self):
        source = {"PATH": "/fixture/bin", "DISPLAY": ":fixture",
                  "RS9_GITHUB_READ_TOKEN": "fixture-token", "NODE_OPTIONS": "fixture-hook",
                  **{name: "caller-value" for name in FLAGS}}
        original = dict(source)
        for system in ("x86_64-linux", "aarch64-linux"):
            with self.subTest(system=system):
                env = _nix_application_environment(source, CURRENT_GENERATION, system)
                self.assertEqual({name: env[name] for name in FLAGS}, {name: "1" for name in FLAGS})
                self.assertEqual(env["DISPLAY"], source["DISPLAY"])
                self.assertNotIn("RS9_GITHUB_READ_TOKEN", env)
                self.assertNotIn("NODE_OPTIONS", env)
        self.assertEqual(source, original)

    def test_other_generations_and_platforms_preserve_the_existing_environment_policy(self):
        source = {"PATH": "/fixture/bin", "DISPLAY": ":fixture", **{name: "1" for name in FLAGS}}
        for generation, system in ((HISTORICAL_GENERATION, "x86_64-linux"),
                                   (HISTORICAL_GENERATION, "aarch64-linux"),
                                   (CURRENT_GENERATION, "aarch64-darwin")):
            with self.subTest(generation=generation, system=system):
                self.assertEqual(_nix_application_environment(source, generation, system),
                                 {"PATH": "/fixture/bin", "DISPLAY": ":fixture"})

    def test_flags_survive_repeated_filtering_and_the_actual_env_restoration_tail(self):
        env = _nix_application_environment(
            {"PATH": str(Path(sys.executable).parent), "DISPLAY": ":fixture",
             "ACTIONS_RUNTIME_TOKEN": "fixture-token"}, CURRENT_GENERATION, "x86_64-linux")
        env = runtime_environment(runtime_environment(env))
        with patch("rs9.hosted_commands.os.getuid", return_value=1001), patch(
                "rs9.hosted_commands.os.getgid", return_value=1001):
            argv = linux_runtime_prefix(env)
        self.assertEqual(argv[:10], ["sudo", "-n", "unshare", "--net", "--", "setpriv",
                                    "--reuid=1001", "--regid=1001", "--clear-groups", "--"])
        # Only the env-restoration tail runs locally; privilege/network controls do not.
        result = subprocess.run([*argv[10:], sys.executable, "-I", "-B", "-c",
                                 "import json,os; print(json.dumps(dict(os.environ)))"],
                                env={"ACTIONS_RUNTIME_TOKEN": "fixture-token"},
                                capture_output=True, text=True, check=True, timeout=10)
        observed = json.loads(result.stdout)
        for name in FLAGS:
            self.assertEqual(observed[name], "1")
        self.assertNotIn("ACTIONS_RUNTIME_TOKEN", observed)
