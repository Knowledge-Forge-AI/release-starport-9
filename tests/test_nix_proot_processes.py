"""Real bounded process and signal boundaries; fake transport is not native PRoot."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

from rs9.nix_proot import _OBSERVER, _external_sigterm, bounded_guest_run
from rs9.nix_proot_wait import GUEST_SUPERVISOR_SOURCE, SOURCE_SHA256, argv_digest, read_frame


class RuntimeProcessTests(unittest.TestCase):
    def test_observer_exec_failure_has_errno_and_closes_its_stream(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            spec = base / "spec.json"
            spec.write_text(json.dumps({"exe": str(base / "absent"), "args": [], "expected": [],
                                        "hold": 1, "until_webkit": False, "glibc_lib": "/guest/lib", "allowed": []}))
            result = subprocess.run([sys.executable, "-W", "error::ResourceWarning", "-c", _OBSERVER, str(spec)],
                                    capture_output=True, timeout=10)
            record = json.loads(result.stdout)
            self.assertFalse(record["started"])
            self.assertEqual(record["launch_errno"], 2)
            self.assertEqual(record["cause_role"], "released-launcher-exec")
            self.assertNotIn(str(base), result.stdout.decode())
            self.assertNotIn(b"ResourceWarning", result.stderr)

    def test_timeout_retains_actual_streams_and_killed_status(self):
        code = "import os,time;os.write(1,b'before-timeout');os.write(2,b'causal-stderr');time.sleep(60)"
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            bounded_guest_run([sys.executable, "-c", code], env=dict(os.environ), timeout=0.2)
        self.assertEqual(caught.exception.output, b"before-timeout")
        self.assertEqual(caught.exception.stderr, b"causal-stderr")
        self.assertEqual(caught.exception.returncode, -signal.SIGKILL)

    def test_created_group_descendants_stop_after_parent_exit_and_timeout(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            for timeout in (False, True):
                marker = base / ("timeout" if timeout else "normal")
                child = ("import pathlib,time,sys\np=pathlib.Path(sys.argv[1])\n"
                         "while True:\n    p.write_text(str(time.monotonic()));time.sleep(.02)\n")
                parent = ("import subprocess,sys,time\nsubprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]])\n"
                          "time.sleep(60 if sys.argv[3]=='timeout' else .15)\n")
                try:
                    bounded_guest_run([sys.executable, "-c", parent, child, str(marker), "timeout" if timeout else "normal"],
                                      env=dict(os.environ), timeout=0.3 if timeout else 3)
                except subprocess.TimeoutExpired:
                    self.assertTrue(timeout)
                first = marker.read_text()
                time.sleep(0.1)
                self.assertEqual(marker.read_text(), first)

    def signal_runtime(self, base, *, forwards):
        guest_tmp = base / "guest-tmp"
        guest_tmp.mkdir()
        proc_root = base / "proc"
        proc_root.mkdir()
        fake = base / "transport.py"
        # Execute the exact guest source with only its bound /tmp file opens
        # translated; the created child is the sole forwarding target.
        fake.write_text("""import json,os,signal,subprocess,sys
prefix='import builtins\\n_real_open=builtins.open\\nbuiltins.open=lambda p,*a,**k:_real_open('+repr(sys.argv[1])+"+p[4:] if isinstance(p,str) and p.startswith('/tmp/') else p,*a,**k)\\n"
command=json.loads(sys.argv[3]);code=command[-1]
with subprocess.Popen([sys.executable,'-c',prefix+code]) as child:
    def forward(sig,frame):
        try:child.send_signal(sig)
        except ProcessLookupError:pass
    signal.signal(signal.SIGTERM,forward if sys.argv[2]=='yes' else signal.SIG_IGN)
    rc=child.wait()
sys.exit(255 if rc<0 else rc)
""")
        return SimpleNamespace(layout=SimpleNamespace(tmp_dir=guest_tmp), facts={"python": sys.executable}, prefix=[],
                               argv=lambda cmd: [sys.executable, str(fake), str(guest_tmp), "yes" if forwards else "no", json.dumps(cmd)],
                               popen=subprocess.Popen, host_env=lambda: dict(os.environ), sleep=time.sleep,
                               proc_root=proc_root, timeouts={})

    def test_real_outer_forwarding_and_group_control_name_their_targets(self):
        with tempfile.TemporaryDirectory() as temp:
            rt = self.signal_runtime(Path(temp), forwards=True)
            result = _external_sigterm(rt, "external-real-fake-transport")
            self.assertEqual(result["status"], "pass", result)
            details = result["details"]
            self.assertTrue(details["guest_handler_observed"])
            self.assertTrue(details["process_group_control"]["guest_handler_observed"])
            self.assertFalse(details["supervisor_added"])
            self.assertEqual(details["group_control_layers"][0], "created-process-group")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux /proc owned-child state readback unavailable on Darwin")
    def test_linux_forced_kill_has_no_signal_compatibility_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            channel = Path(temp)
            code = "import os,signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"
            command = [sys.executable, "-c", code]
            expected = {"nonce": "1" * 32, "binding": "2" * 64,
                        "source_sha256": SOURCE_SHA256, "argv_sha256": argv_digest(command)}
            argv = [sys.executable, "-c", GUEST_SUPERVISOR_SOURCE, str(channel),
                    expected["nonce"], expected["binding"], SOURCE_SHA256, expected["argv_sha256"], "--", *command]
            with self.assertRaises(subprocess.TimeoutExpired):
                bounded_guest_run(argv, env=dict(os.environ), timeout=1)
            started = read_frame(channel / "started.json", expected, started=True)
            self.assertEqual(started["status"], "valid")
            self.assertEqual(read_frame(channel / "final.json", expected)["status"], "missing")
            child_stat = Path("/proc") / str(started["record"]["child_pid"]) / "stat"
            # The exact recorded child belongs to this created process group.
            # Zombie state proves termination, without claiming subreaper reaping.
            for _ in range(20):
                try:
                    state = child_stat.read_text().rsplit(") ", 1)[1].split()[0]
                except FileNotFoundError:
                    break
                if state == "Z":
                    break
                time.sleep(0.05)
            else:
                self.fail("owned child survived forced group cleanup")
