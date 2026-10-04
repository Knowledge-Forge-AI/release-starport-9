"""Released runtime harnesses must not inherit capture or Actions credentials."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.hosted_smoke import verify_nebular_runtime


class SmokeEnvironmentTests(unittest.TestCase):
    def test_released_verifier_receives_only_runtime_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "bin").mkdir()
            (root / "bin/tfsb-studio-service").write_bytes(b"fixture")
            (root / "lib/sidecar-payload").mkdir(parents=True)
            (root / "lib/sidecar-payload/manifest.json").write_text("{}")
            prepared = {"scratch": root, "tools": root}
            env = {"PATH": "/usr/bin", "HOME": str(root), "THEME_FORGE_CACHE_DIR": str(root / "cache"),
                   "RS9_GITHUB_READ_TOKEN": "fixture-read-token", "ACTIONS_RUNTIME_TOKEN": "fixture-actions-token"}
            with patch("rs9.hosted_smoke.subprocess.run", return_value=SimpleNamespace(returncode=1)) as run:
                with self.assertRaises(ContractError):
                    verify_nebular_runtime(root, prepared, "x86_64-linux", env=env)
            observed = run.call_args.kwargs["env"]
            self.assertEqual(observed, {k: env[k] for k in ("PATH", "HOME", "THEME_FORGE_CACHE_DIR")})
