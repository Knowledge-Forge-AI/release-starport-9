"""Synthetic hooks retain the shared production consumer's guard behavior."""
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9 import tf_pypi_consumer as consumer
from rs9.tf_pypi_archive import AdmissionError


class UniversalGuardCoreTests(unittest.TestCase):
    def exercise(self, *, orphans=0, scratch_change=False, real_change=False, mutate_setup=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        work = root / "consumer"
        manifest_sha = "a" * 64
        relative = ".cache/rs9/theme-forge-nebular-fusion/entries/" + manifest_sha + "/payload/fixture/bin/gui"
        gui = work / "home" / relative
        body = b"synthetic GUI, never executed"
        native = {"command": "tfnf", "scenario": "C", "timeout_seconds": 30,
                  "state_paths": [], "smoke_support": {"fixture": True}}
        capture = {"root": root, "native": native, "manifest_sha256": manifest_sha,
                   "manifest": {"members": [{"path": "fixture"}]},
                   "gui": {"sha256": hashlib.sha256(body).hexdigest(),
                           "materialized_path": "fixture/bin/gui"}}
        calls = []
        def create_venv(path):
            (path / "bin").mkdir(parents=True)
            for name in ("python", "tfnf"):
                (path / "bin" / name).write_text("synthetic executable, never run")
                (path / "bin" / name).chmod(0o755)
        def process(argv, env, _work, prefix, timeout, *, runner):
            self.assertNotIn("MUTATED", env)
            self.assertEqual(prefix, ["network-denial"])
            calls.append([str(x) for x in argv])
            stdout = ""
            if "--version" in argv:
                stdout = "theme-forge-nebular-fusion 0.7.0\n"
            if "--path" in argv:
                stdout = str(gui) + "\n"
            return {"exit_code": 0, "signal": None, "stdout_token": stdout,
                    "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                    "cleanup_known": True, "output_complete": True, "forced_cleanup": False}
        def setup(**kwargs):
            self.assertEqual(kwargs["prefix"], ("network-denial",))
            if mutate_setup:
                kwargs["env"]["MUTATED"] = "synthetic"
            gui.parent.mkdir(parents=True)
            gui.write_bytes(body)
            gui.chmod(0o755)
            return {"schema": "synthetic-setup"}
        def state(phase, target):
            return {"schema": "nebular.native-rc-persistent-user-state-v1",
                    "method": "native-rc-smoke.persistentStateLocations+snapshotLocations",
                    "scope": "real-user-state", "target": target, "phase": phase,
                    "locations": 1, "snapshot_sha256": ("b" if real_change and phase == "after" else "a") * 64,
                    "changed": []}
        native_probe = {"exit_code": 0, "signal": None, "stdout_sha256": "b" * 64,
                        "stderr_sha256": "c" * 64, "cleanup_known": True,
                        "output_complete": True, "forced_cleanup": False}
        with patch.object(consumer.venv, "EnvBuilder", return_value=SimpleNamespace(create=create_venv)), \
             patch.object(consumer, "_nebular_run", side_effect=process), \
             patch("rs9.nebular070_smoke_support.materialize_smoke_support", return_value={}), \
             patch("rs9.nebular070_smoke_support.installed_runtime_root", return_value=root), \
             patch("rs9.nebular070_installed_smoke.run_installed_smoke", return_value={"native_probe": native_probe}):
            return consumer._nebular_installed_consumer(
                capture, root / "fixture.whl", work, target="linux-x64-gnu",
                sandbox_prefix=["network-denial"],
                sandbox_probe=lambda env, prefix: {"network_disabled": True, "method": "synthetic"},
                process_observer=lambda work, it=iter([0, orphans]): {"orphan_count": next(it)},
                state_snapshot=lambda home, paths, it=iter([0, int(scratch_change)]): {"fixture": next(it)},
                real_user_state_snapshot=state, runtime_setup=setup)

    def test_setup_gets_copied_env_and_immutable_prefix(self):
        result = self.exercise(mutate_setup=True)
        self.assertEqual(result["runtime_setup"]["schema"], "synthetic-setup")
        self.assertEqual(result["cleanup"], {"pip_uninstall_exit": 0, "orphan_processes": 0})

    def test_orphans_still_refuse_after_setup(self):
        with self.assertRaisesRegex(AdmissionError, "ORPHAN_PROCESSES"):
            self.exercise(orphans=1)

    def test_scratch_state_changes_still_refuse_after_setup(self):
        with self.assertRaisesRegex(AdmissionError, "NEBULAR_USER_STATE"):
            self.exercise(scratch_change=True)

    def test_real_user_state_changes_still_refuse_after_setup(self):
        with self.assertRaisesRegex(AdmissionError, "USER_STATE_GUARD"):
            self.exercise(real_change=True)
