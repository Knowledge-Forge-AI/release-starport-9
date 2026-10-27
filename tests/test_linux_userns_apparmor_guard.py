"""Stub-only contract tests for the proposed Linux Nix sysctl guard.

These tests never touch the host kernel.  Every sysctl and sudo call resolves
to a temporary fixture executable, and the lane command is a disposable shell
fixture.
"""
from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import tempfile
import textwrap
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / ".github/scripts/rs9-linux-userns-apparmor-guard.sh"
KEY = "kernel.apparmor_restrict_unprivileged_userns"


class LinuxUsernsGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.state = self.root / "state"
        self.log = self.root / "log"
        self.state.write_text("1\n", encoding="utf-8")
        self.log.write_text("", encoding="utf-8")
        self._write_stub(
            "sysctl",
            r'''#!/bin/sh
set -eu
state=${RS9_STUB_STATE:?}
log=${RS9_STUB_LOG:?}
key=kernel.apparmor_restrict_unprivileged_userns
if [ "$#" -eq 2 ] && [ "$1" = "-n" ] && [ "$2" = "$key" ]; then
  if [ "${RS9_STUB_LIE_AFTER_RESTORE-}" = "1" ] && [ -f "$state.restored" ]; then
    printf '0\n'
  else
    cat "$state"
  fi
  exit 0
fi
if [ "$#" -eq 2 ] && [ "$1" = "-w" ]; then
  value=${2#*=}
  printf 'set %s\n' "$value" >> "$log"
  printf '%s\n' "$value" > "$state"
  if [ "$value" = "1" ]; then : > "$state.restored"; fi
  exit 0
fi
exit 64
''',
        )
        self._write_stub(
            "sudo",
            r'''#!/bin/sh
set -eu
if [ "${1-}" = "-n" ]; then shift; fi
if [ "${RS9_STUB_FAIL_VALUE-}" != "" ] && [ "${3#*=}" = "$RS9_STUB_FAIL_VALUE" ]; then
  exit 43
fi
exec "$@"
''',
        )

    def tearDown(self):
        self.temp.cleanup()

    def _write_stub(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        path.chmod(0o755)

    def _env(self, **updates: str) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "GITHUB_ACTIONS": "true",
                "RUNNER_OS": "Linux",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9",
                "RS9_STUB_STATE": str(self.state),
                "RS9_STUB_LOG": str(self.log),
                "PATH": f"{self.bin}:{env['PATH']}",
            }
        )
        env.update(updates)
        return env

    def _run(self, command: list[str], **env_updates: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(GUARD), "--", *command],
            env=self._env(**env_updates),
            text=True,
            capture_output=True,
            check=False,
        )

    def test_original_zero_is_noop(self):
        self.state.write_text("0\n", encoding="utf-8")
        result = self._run(["/bin/sh", "-c", "exit 0"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state.read_text(encoding="utf-8"), "0\n")
        self.assertEqual(self.log.read_text(encoding="utf-8"), "")

    def test_original_zero_is_restored_if_lane_mutates_it(self):
        self.state.write_text("0\n", encoding="utf-8")
        result = self._run(["/bin/sh", "-c", "printf '1\\n' > \"$RS9_STUB_STATE\""])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state.read_text(encoding="utf-8"), "0\n")
        self.assertEqual(self.log.read_text(encoding="utf-8").splitlines(), ["set 0"])

    def test_original_one_admits_then_restores(self):
        result = self._run(["/bin/sh", "-c", "exit 0"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state.read_text(encoding="utf-8"), "1\n")
        self.assertEqual(self.log.read_text(encoding="utf-8").splitlines(), ["set 0", "set 1"])

    def test_lane_failure_is_preserved_and_restored(self):
        result = self._run(["/bin/sh", "-c", "exit 37"])
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertEqual(self.state.read_text(encoding="utf-8"), "1\n")

    def test_admission_failure_runs_no_lane_and_fails_closed(self):
        marker = self.root / "ran"
        result = self._run(
            ["/bin/sh", "-c", "printf ran > \"$RS9_STUB_MARKER\""],
            RS9_STUB_FAIL_VALUE="0",
            RS9_STUB_MARKER=str(marker),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertEqual(self.state.read_text(encoding="utf-8"), "1\n")

    def test_restore_command_failure_fails_closed(self):
        result = self._run(["/bin/sh", "-c", "exit 0"], RS9_STUB_FAIL_VALUE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.state.read_text(encoding="utf-8"), "0\n")

    def test_restore_verification_failure_fails_closed(self):
        result = self._run(
            ["/bin/sh", "-c", "exit 0"],
            RS9_STUB_LIE_AFTER_RESTORE="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.state.read_text(encoding="utf-8"), "1\n")

    def test_signal_still_restores_original(self):
        process = subprocess.Popen(
            [str(GUARD), "--", "/bin/sh", "-c", "trap 'exit 143' TERM; while :; do sleep 0.1; done"],
            env=self._env(),
            start_new_session=True,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.15)
            os.killpg(process.pid, signal.SIGTERM)
            returncode = process.wait(timeout=5)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        self.assertEqual(returncode, 143)
        self.assertEqual(self.state.read_text(encoding="utf-8"), "1\n")

    def test_invalid_context_and_sysctl_values_are_rejected(self):
        result = self._run(["/bin/sh", "-c", "exit 0"], GITHUB_ACTIONS="false")
        self.assertNotEqual(result.returncode, 0)
        self.state.write_text("2\n", encoding="utf-8")
        result = self._run(["/bin/sh", "-c", "exit 0"])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.log.read_text(encoding="utf-8"), "")

    def test_self_hosted_context_is_rejected_before_host_calls(self):
        marker = self.root / "ran-self-hosted"
        result = self._run(
            ["/bin/sh", "-c", "printf ran > \"$RS9_STUB_MARKER\""],
            RUNNER_ENVIRONMENT="self-hosted",
            RS9_STUB_MARKER=str(marker),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertEqual(self.log.read_text(encoding="utf-8"), "")

    def test_workflow_routes_linux_guard_and_darwin_direct_without_host_calls(self):
        workflow = (ROOT / ".github/workflows/rs9-candidate-tests.yml").read_text(encoding="utf-8")
        step_start = workflow.index("- name: Execute non-production nix lane")
        step_end = workflow.index("      - uses: actions/upload-artifact@", step_start)
        nix_step = workflow[step_start:step_end]
        self.assertIn("if: ${{ !cancelled() }}", nix_step)
        linux_start = nix_step.index("if [[ \"${RUNNER_OS-}\" == 'Linux' ]]; then")
        darwin_start = nix_step.index("elif [[ \"${RUNNER_OS-}\" == 'macOS' ]]; then", linux_start)
        else_start = nix_step.index("else\n", darwin_start)
        linux_branch = nix_step[linux_start:darwin_start]
        darwin_branch = nix_step[darwin_start:else_start]
        else_branch = nix_step[else_start:]
        self.assertIn("rs9-linux-userns-apparmor-guard.sh --", linux_branch)
        self.assertNotIn("rs9-linux-userns-apparmor-guard.sh", darwin_branch)
        self.assertIn(
            "\n          python3 -m rs9.hosted_pipeline 'nix' --system '${{ matrix.system }}' --scratch \"$RUNNER_TEMP/rs9-work\" --receipts \"$RUNNER_TEMP/rs9-output\" --inputs \"$RUNNER_TEMP/rs9-inputs\"\n",
            darwin_branch,
        )
        self.assertNotIn("sysctl", darwin_branch)
        self.assertNotIn("sudo", darwin_branch)
        self.assertIn("Unsupported runner OS for the maintained nix matrix", else_branch)
        self.assertIn("exit 78", else_branch)


if __name__ == "__main__":
    unittest.main()
