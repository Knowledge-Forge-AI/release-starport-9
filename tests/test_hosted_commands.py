import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.hosted_commands import linux_runtime_prefix, probes_for, run_probes, service_protocol


class SupportedCommandsTests(unittest.TestCase):
    def test_runtime_environment_survives_sudo_reset_without_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            env = {"PATH": str(Path(sys.executable).parent), "HOME": str(root),
                   "THEME_FORGE_CACHE_DIR": str(root / "cache"),
                   "XDG_CACHE_HOME": str(root / "xdg"),
                   "RS9_GITHUB_READ_TOKEN": "fixture-read-token",
                   "ACTIONS_RUNTIME_TOKEN": "fixture-actions-token"}
            with patch("rs9.hosted_commands.os.getuid", return_value=1001), patch(
                    "rs9.hosted_commands.os.getgid", return_value=1001):
                prefix = linux_runtime_prefix(env)
            self.assertEqual(prefix[:10], ["sudo", "-n", "unshare", "--net", "--", "setpriv",
                                          "--reuid=1001", "--regid=1001", "--clear-groups", "--"])
            # Execute the actual env-restoration tail with sudo-like reset input.
            # Namespace/privilege behavior is exercised only by hosted runners.
            script = ("import json,os; from pathlib import Path; "
                      "p=Path(os.environ['THEME_FORGE_CACHE_DIR']); p.mkdir(); "
                      "print(json.dumps(dict(os.environ)))")
            result = subprocess.run([*prefix[10:], Path(sys.executable).name, "-c", script],
                                    env={"HOME": "/root", "PATH": "/unavailable",
                                         "ACTIONS_RUNTIME_TOKEN": "fixture-actions-token"},
                                    capture_output=True, text=True, check=True, timeout=10)
            observed = json.loads(result.stdout)
            for key in ("PATH", "HOME", "THEME_FORGE_CACHE_DIR", "XDG_CACHE_HOME"):
                self.assertEqual(observed[key], env[key])
            self.assertNotIn("RS9_GITHUB_READ_TOKEN", observed)
            self.assertNotIn("ACTIONS_RUNTIME_TOKEN", observed)
            self.assertTrue((root / "cache").is_dir())

    def test_runtime_prefix_refuses_root_identity(self):
        for uid, gid in ((0, 1001), (1001, 0)):
            with patch("rs9.hosted_commands.os.getuid", return_value=uid), patch(
                    "rs9.hosted_commands.os.getgid", return_value=gid):
                with self.assertRaises(ContractError) as error:
                    linux_runtime_prefix({})
                self.assertEqual(error.exception.code, "UNPRIVILEGED_CLIENT_REQUIRED")

    def test_unbound_release_cannot_pass_probes(self):
        gates = run_probes("tfsb", "/unavailable")
        self.assertEqual(gates[0]["status"], "not-run")

    def test_service_has_protocol_probe_and_batch_empty_input(self):
        service = probes_for("tfsb-studio-service")
        self.assertEqual(service[0]["kind"], "service-protocol")
        self.assertEqual(service[0]["argv"], [])
        batch = probes_for("tfsl-batch")[0]
        self.assertEqual(batch["input"], "")
        self.assertEqual(batch["expect_exit"], 1)
        self.assertIn("EMPTY_INPUT", batch["stdout_contains"])

    def test_actual_ndjson_negotiation_and_shutdown(self):
        script = '''import json,sys
for line in sys.stdin:
    r=json.loads(line)
    if r['method']=='initialize':
        print(json.dumps({'jsonrpc':'2.0','id':r['id'],'result':{'selectedVersion':'1.0','sessionNonce':'fixture'}}),flush=True)
    elif r['method']=='shutdown':
        assert r['params']['sessionNonce']=='fixture'
        print(json.dumps({'jsonrpc':'2.0','id':r['id'],'result':None}),flush=True)
    elif r['method']=='exit': break
'''
        result = service_protocol([sys.executable, "-u", "-c", script])
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["selected_version"], "1.0")

    def test_protocol_error_fails_without_metadata_fallback(self):
        script = "import json; input(); print(json.dumps({'jsonrpc':'2.0','id':1,'error':{'code':-1}}),flush=True)"
        with self.assertRaises(ContractError):
            service_protocol([sys.executable, "-u", "-c", script])
