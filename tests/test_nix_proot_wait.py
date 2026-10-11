"""Adverse framing and real guest supervisor processes, with a fake PRoot boundary."""
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from rs9.nix_proot import Run, bounded_guest_run
from rs9.nix_proot_wait import SCHEMA, SOURCE_SHA256, assess_status, diagnostic_guest_run, read_frame


class WaitFrames(unittest.TestCase):
    def frame(self, **changes):
        record = {"schema": SCHEMA, "nonce": "a" * 32, "binding": "b" * 64,
                  "source_sha256": SOURCE_SHA256, "argv_sha256": "c" * 64,
                  "supervisor_pid": 100, "child_pid": 101, "kind": "exited", "exit_code": 255,
                  "signal": None, "core_dumped": False, "forwarded_signals": []}
        return {**record, **changes}

    def read(self, raw):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "frame"
            path.write_bytes(raw)
            expected = {k: self.frame()[k] for k in ("nonce", "binding", "source_sha256", "argv_sha256")}
            return read_frame(path, expected)

    def test_deliberate_255_and_ordinary_status_contradiction(self):
        frame = self.read(json.dumps(self.frame()).encode())
        result = assess_status(255, frame)
        self.assertTrue(result["deliberate_exit_255"])
        self.assertTrue(result["compatible_status"])
        self.assertFalse(result["status_mapped"])
        result = assess_status(7, frame)
        self.assertEqual(result["status"], "contradictory")
        self.assertEqual(result["raw_returncode"], 7)

    def test_signal_collapse_is_exposed_and_never_rewritten(self):
        frame = self.read(json.dumps(self.frame(kind="signaled", exit_code=None, signal=15)).encode())
        for raw in (-15, 143, 255, 7):
            with self.subTest(raw=raw):
                result = assess_status(raw, frame)
                self.assertEqual(result["raw_returncode"], raw)
                self.assertEqual(result["compatible_status"], raw in (-15, 143))
                self.assertFalse(result["status_mapped"])
        self.assertEqual(assess_status(7, frame)["status"], "contradictory")

    def test_each_missing_key_bad_type_binding_and_schema_is_rejected(self):
        record = self.frame()
        for key in record:
            candidate = dict(record)
            del candidate[key]
            with self.subTest(missing=key):
                self.assertEqual(self.read(json.dumps(candidate).encode())["status"], "malformed")
        for key, value in (("schema", "wrong"), ("nonce", "a" * 33), ("nonce", "d" * 32),
                           ("binding", []), ("source_sha256", "d" * 64), ("argv_sha256", "d" * 64),
                           ("supervisor_pid", True), ("child_pid", 100), ("kind", []),
                           ("exit_code", True), ("exit_code", 256), ("exit_code", -1),
                           ("signal", 15), ("core_dumped", 1), ("core_dumped", True),
                           ("forwarded_signals", [15, 15]), ("forwarded_signals", [True]),
                           ("forwarded_signals", [9])):
            with self.subTest(key=key, value=value):
                self.assertNotEqual(self.read(json.dumps(self.frame(**{key: value})).encode())["status"], "valid")
        for update in ({"kind": "signaled", "signal": 15}, {"kind": "signaled", "exit_code": None, "signal": 0},
                       {"kind": "signaled", "exit_code": None, "signal": 65}, {"extra": "value"}):
            self.assertEqual(self.read(json.dumps(self.frame(**update)).encode())["status"], "malformed")

    def test_duplicate_keys_trailing_data_oversize_and_bad_json(self):
        for raw in (b"not json", b"[]", b"x" * 4097, json.dumps(self.frame()).encode() + b"{}",
                    json.dumps(self.frame()).encode()[:-1] + b',"exit_code":255}',
                    b'{"schema":NaN}', b'\xff'):
            with self.subTest(raw=raw[:20]):
                self.assertEqual(self.read(raw)["status"], "malformed")

    def test_missing_symlink_directory_fifo_and_owner_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            expected = {k: self.frame()[k] for k in ("nonce", "binding", "source_sha256", "argv_sha256")}
            self.assertEqual(read_frame(base / "missing", expected)["status"], "missing")
            path = base / "real"
            path.write_text(json.dumps(self.frame()))
            link = base / "link"
            link.symlink_to(path)
            self.assertEqual(read_frame(link, expected)["status"], "malformed")
            self.assertEqual(read_frame(base, expected)["status"], "malformed")
            fifo = base / "fifo"
            os.mkfifo(fifo)
            self.assertEqual(read_frame(fifo, expected)["status"], "malformed")
            with patch("rs9.nix_proot_wait.os.getuid", return_value=os.getuid() + 1):
                self.assertEqual(read_frame(path, expected)["status"], "malformed")


class RealWaitProcesses(unittest.TestCase):
    def runtime(self, base, *, collapse=True):
        script = base / "fake-proot.py"
        script.write_text("import subprocess,sys\nwith subprocess.Popen(sys.argv[1:]) as child:\n"
                          "    rc=child.wait()\n" + ("sys.exit(255 if rc<0 else rc)\n" if collapse else "sys.exit(7)\n"))

        def run(probe, command, **kwargs):
            argv = list(command)
            # The exact guest source is executed; only its explicitly bound
            # /tmp channel is translated by this fake PRoot filesystem seam.
            argv[6] = str(base / Path(argv[6]).name)
            start = time.monotonic()
            result = bounded_guest_run([sys.executable, str(script), *argv], env=dict(os.environ),
                                       timeout=kwargs["timeout"])
            return Run(result.returncode, result.stdout, result.stderr, time.monotonic() - start, None)

        return SimpleNamespace(layout=SimpleNamespace(tmp_dir=base), facts={"python": sys.executable}, run=run)

    def test_real_deliberate_255_and_signal_collapse_have_distinct_records(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            rt = self.runtime(base)
            for code, expected_kind in (("import sys;sys.exit(255)", "exited"),
                                        ("import os,signal;os.kill(os.getpid(),signal.SIGTERM)", "signaled")):
                raw, diag = diagnostic_guest_run(rt, "real-fake-proot", [sys.executable, "-c", code])
                self.assertEqual(raw.returncode, 255)
                self.assertEqual(diag["record"]["kind"], expected_kind)
                self.assertEqual(diag["compatible_status"], expected_kind == "exited")
                self.assertFalse(diag["status_mapped"])
                self.assertFalse(diag["authenticated"])
                self.assertNotIn(str(base), json.dumps(diag))
                self.assertEqual(list(base.rglob("host-diagnostic.json")), [])

    def test_real_ordinary_exit_contradiction_is_not_promoted(self):
        with tempfile.TemporaryDirectory() as temp:
            rt = self.runtime(Path(temp), collapse=False)
            raw, diag = diagnostic_guest_run(rt, "contradiction", [sys.executable, "-c", "raise SystemExit(42)"])
            self.assertEqual(raw.returncode, 7)
            self.assertEqual(diag["status"], "contradictory")
            self.assertFalse(diag["compatible_status"])

    def test_real_sigkill_re_raises_without_supervisor_traceback(self):
        with tempfile.TemporaryDirectory() as temp:
            rt = self.runtime(Path(temp))
            raw, diag = diagnostic_guest_run(rt, "kill", [sys.executable, "-c",
                "import os,signal;os.kill(os.getpid(),signal.SIGKILL)"])
            self.assertEqual(raw.returncode, 255)
            self.assertEqual((diag["record"]["kind"], diag["record"]["signal"]), ("signaled", 9))
            self.assertFalse(diag["compatible_status"])
            self.assertNotIn(b"Traceback", raw.stderr)

    def test_missing_frames_cannot_claim_compatibility(self):
        with tempfile.TemporaryDirectory() as temp:
            rt = SimpleNamespace(layout=SimpleNamespace(tmp_dir=Path(temp)), facts={"python": sys.executable},
                                 run=lambda *a, **k: Run(255, b"", b"", 0.01, None))
            raw, diag = diagnostic_guest_run(rt, "missing", [sys.executable, "-c", "pass"])
            self.assertEqual(diag["status"], "missing")
            self.assertEqual(raw.returncode, 255)
            self.assertFalse(diag["compatible_status"])

    def test_guest_precreated_host_filename_does_not_abort_or_supply_host_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            def run(probe, command, **kwargs):
                channel = base / Path(command[6]).name
                (channel / "host-diagnostic.json").write_text('{"compatible_status":true}')
                return Run(255, b"", b"", 0.01, None)
            rt = SimpleNamespace(layout=SimpleNamespace(tmp_dir=base), facts={"python": sys.executable}, run=run)
            raw, diag = diagnostic_guest_run(rt, "guest-precreated", [sys.executable, "-c", "pass"])
            self.assertEqual(raw.returncode, 255)
            self.assertEqual(diag["status"], "missing")
            self.assertFalse(diag["compatible_status"])

    def test_oversized_host_record_fails_closed_without_an_exception(self):
        with tempfile.TemporaryDirectory() as temp:
            rt = SimpleNamespace(layout=SimpleNamespace(tmp_dir=Path(temp)), facts={"python": sys.executable},
                                 run=lambda *a, **k: Run(255, b"", b"", 0.01, None))
            with patch("rs9.nix_proot_wait.MAX_FRAME", 1):
                raw, diag = diagnostic_guest_run(rt, "oversize", [sys.executable, "-c", "pass"])
            self.assertEqual(raw.returncode, 255)
            self.assertEqual(diag["reason"], "host-wait-frame-limit")
            self.assertFalse(diag["compatible_status"])

    def test_signal_during_child_handler_reset_targets_no_process_group(self):
        with tempfile.TemporaryDirectory() as temp:
            rt = self.runtime(Path(temp))
            original_run = rt.run
            # Inject a real SIGTERM at the inherited-handler boundary in the
            # child, with the exact supervisor source and a fake transport.
            prelude = ("import os,signal\nroot_pid=os.getpid()\nset_signal=signal.signal\n"
                       "def inject(sig,handler):\n"
                       "    if os.getpid()!=root_pid and handler==signal.SIG_DFL and sig==signal.SIGTERM:\n"
                       "        os.kill(os.getpid(),signal.SIGTERM)\n"
                       "    return set_signal(sig,handler)\n"
                       "signal.signal=inject\n")
            def run(probe, command, **kwargs):
                argv = list(command)
                argv[5] = prelude + argv[5]
                return original_run(probe, argv, **kwargs)
            rt.run = run
            raw, diag = diagnostic_guest_run(rt, "fork-reset", [sys.executable, "-c", "pass"])
            self.assertEqual(raw.returncode, 255)
            self.assertEqual((diag["record"]["kind"], diag["record"]["signal"]), ("signaled", 15))
            self.assertFalse(diag["compatible_status"])

    def test_same_nonce_and_argv_cannot_cross_guest_identity_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            bindings = []
            for guest in ("first", "second"):
                channel = base / guest
                channel.mkdir()
                rt = SimpleNamespace(layout=SimpleNamespace(tmp_dir=channel),
                                     facts={"python": sys.executable, "guest_root": "/guest/" + guest}, closure=[],
                                     run=lambda *a, **k: Run(255, b"", b"", 0.01, None))
                with patch("rs9.nix_proot_wait.secrets.token_hex", return_value="a" * 32):
                    _, diagnostic = diagnostic_guest_run(rt, "same-probe", [sys.executable, "-c", "pass"])
                bindings.append((diagnostic["binding"], diagnostic["guest_sha256"]))
            self.assertNotEqual(bindings[0][0], bindings[1][0])
            self.assertNotEqual(bindings[0][1], bindings[1][1])
