"""Deterministic custody checks; no operating-system PID is signaled."""
from __future__ import annotations

import errno
import signal
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rs9 import tf_pypi_consumer as consumer


class FakeStream:
    def __init__(self, fd):
        self.fd = fd

    def fileno(self):
        return self.fd

    def close(self):
        pass


class FakeRun:
    pid = 987654321

    def __init__(self, *, flood_at=None, exit_at=0.1, group="persistent"):
        self.now = 0.0
        self.flood_at = flood_at
        self.exit_at = exit_at
        self.group = group
        self.first_exit = None
        self.sent_data = False
        self.killed = False
        self.signals = []
        self.keys = {}
        self.forced_code = None
        self.child = SimpleNamespace(
            pid=self.pid,
            stdout=FakeStream(101) if flood_at is not None else None,
            stderr=FakeStream(102) if flood_at is not None else None,
            poll=self.poll,
            wait=lambda timeout=None: self.poll(),
            kill=lambda: setattr(self, "forced_code", -9),
            send_signal=lambda number: self.signals.append((number, self.now)),
        )

    def poll(self):
        code = self.forced_code if self.forced_code is not None else (
            0 if self.now >= self.exit_at else None)
        if code is not None and self.first_exit is None:
            self.first_exit = self.now
        return code

    def sleep(self, seconds):
        self.now += max(0.001, seconds)

    def register(self, fd, _events, data):
        self.keys[fd] = SimpleNamespace(fd=fd, data=data)

    def unregister(self, fd):
        self.keys.pop(fd, None)

    def select(self, timeout):
        self.sleep(timeout)
        return [(key, 1) for fd, key in list(self.keys.items())
                if fd == 102 or self.now >= self.flood_at]

    def close(self):
        self.keys.clear()

    def read(self, fd, _count):
        if fd == 102 or self.sent_data:
            return b""
        self.sent_data = True
        return b"overflow"

    def exists(self):
        if self.group == "persistent":
            return not self.killed
        if self.group == "released-reused":
            return self.now < 0.2 or self.now >= 0.3
        if self.group == "timeout-released-reused":
            return self.now < 0.25 or self.now >= 0.4
        raise AssertionError("unknown synthetic group")

    def killpg(self, pid, number):
        # Replace every OS group probe and signal for this fake PID.
        if pid != self.pid:
            raise AssertionError("foreign synthetic PID")
        if number == 0:
            if not self.exists():
                raise ProcessLookupError(errno.ESRCH, "synthetic absence")
            return
        self.signals.append((number, self.now))
        if number == signal.SIGKILL:
            self.killed = True

    def run(self, *, timeout=5):
        with patch("rs9.tf_pypi_consumer.time.monotonic", side_effect=lambda: self.now), patch(
                "rs9.tf_pypi_consumer.time.sleep", side_effect=self.sleep), patch(
                "rs9.tf_pypi_consumer.selectors.DefaultSelector", return_value=self), patch(
                "rs9.tf_pypi_consumer.os.set_blocking"), patch(
                "rs9.tf_pypi_consumer.os.read", side_effect=self.read), patch(
                "rs9.tf_pypi_consumer.os.killpg", side_effect=self.killpg), patch(
                "rs9.tf_pypi_consumer._NEBULAR_MAX_OUTPUT", 4):
            return consumer._nebular_run(["synthetic"], {}, Path("."), (), timeout,
                                        runner=lambda *args, **kwargs: self.child)


class ProcessCustodyTests(unittest.TestCase):
    def test_late_post_exit_cap_uses_original_cleanup_deadline(self):
        fake = FakeRun(flood_at=0.25)
        result = fake.run()
        kills = [when for number, when in fake.signals if number == signal.SIGKILL]
        self.assertEqual(len(kills), 1)
        self.assertLessEqual(kills[0], fake.first_exit + 0.51)
        self.assertLessEqual(fake.now, fake.first_exit + 1.01)
        self.assertTrue(result["output_limit_exceeded"])
        self.assertTrue(result["forced_cleanup"])
        self.assertTrue(result["cleanup_known"])
        self.assertFalse(result["output_complete"])

    def test_released_group_is_not_signaled_by_later_escaped_writer(self):
        fake = FakeRun(flood_at=0.4, group="released-reused")
        result = fake.run()
        self.assertEqual(fake.signals, [])
        self.assertTrue(result["output_limit_exceeded"])
        self.assertTrue(result["forced_cleanup"])
        self.assertFalse(result["cleanup_known"])

    def test_timeout_cannot_kill_reused_group_after_observed_release(self):
        fake = FakeRun(exit_at=0.2, group="timeout-released-reused")
        result = fake.run(timeout=0.1)
        self.assertEqual([number for number, _when in fake.signals], [signal.SIGTERM])
        self.assertTrue(result["timed_out"])
        self.assertTrue(result["forced_cleanup"])
        self.assertFalse(result["cleanup_known"])


if __name__ == "__main__":
    unittest.main()
