"""Pure SDK/inventory transport composition; no scanner or native tool runs."""
import base64
from functools import lru_cache
import inspect
import sys
import unittest
from unittest.mock import Mock, patch

from rs9 import archarm_sdk as sdk
from rs9 import client_inventory as inventory
from rs9._archarm_support import process
from rs9.build_native import SubprocessRunner
from rs9.errors import ContractError
from rs9.hosted_deb import RecordingRunner
from tests.test_archarm_capture import DuckGuard
from tests.test_archarm_sdk_roles import RoleTestBase
from tests.test_client_inventory import _make_framed_payload


@lru_cache(maxsize=1)
def large_frame():
    rows = [{"kind": "dir", "mode": 0o755,
             "path": base64.b64encode(("fixture-" + "x" * 140 + f"{i:06d}").encode()).decode()}
            for i in range(36000)]
    return _make_framed_payload(rows)


class InventoryCaptureTests(RoleTestBase):
    def client(self):
        return self.lease.client(
            [(str(self.h.directory("repository")), "/srv/rs9/repository", False)],
            self.h.directory("probe-output"))

    def capture_seams(self, body):
        child = Mock()
        child.returncode = 0
        child.stdout = Mock()
        child.stderr = Mock()

        def read(_child, streams, _selector, _deadline, limit):
            streams[0].data.extend(body[:limit + 1])
            if len(body) > limit:
                return "overflow"
            for stream in streams:
                stream.complete = True
            return "exited"
        return child, read

    def test_large_valid_inventory_reaches_real_parser_and_capture_in_both_wrapper_shapes(self):
        body = large_frame()
        self.assertGreater(len(body), sdk.MAX_WORKER_OUTPUT)
        self.assertLessEqual(len(body), inventory.MAX_STDOUT_BYTES)
        with self.client() as client:
            for guarded in (False, True):
                with self.subTest(guarded=guarded):
                    leaf = SubprocessRunner()
                    guard = DuckGuard(leaf) if guarded else leaf
                    host = RecordingRunner(guard)
                    child, read = self.capture_seams(body)
                    with patch.object(self.lease._s.docker, "host", host), \
                            patch.object(process.subprocess, "Popen", return_value=child) as spawn, \
                            patch.object(process.bp, "_capture", side_effect=read) as capture, \
                            patch.object(process.bp, "_stop", return_value=(True, "complete")) as stop:
                        result = client.inventory("pre-install")
                    self.assertEqual(capture.call_args.args[-1], inventory.MAX_STDOUT_BYTES)
                    self.assertIsInstance(capture.call_args.args[1][1], process._InventoryStderr)
                    stop.assert_not_called()
                    self.assertEqual(len(result), 36000)
                    self.assertEqual(set(result.values()), {"dir:0755"})
                    self.assertEqual(client.last_diagnostics["counters"]["entries"], 36000)
                    self.assertEqual(len(host.receipts), 1)
                    self.assertTrue(host.receipts[0].executed)
                    self.assertIn(inventory.scanner_argv(family="pacman")[-1], spawn.call_args.args[0])
                    if guarded:
                        self.assertEqual(len(guard.calls), 1)
                    self.assertFalse(hasattr(leaf, "_archarm_capture_limit"))

    def test_ordinary_exec_still_overflows_at_eight_mib(self):
        child, read = self.capture_seams(large_frame())
        with self.client() as client:
            with patch.object(self.lease._s.docker, "host", RecordingRunner(SubprocessRunner())), \
                    patch.object(process.subprocess, "Popen", return_value=child), \
                    patch.object(process.bp, "_capture", side_effect=read) as capture, \
                    patch.object(process.bp, "_stop", return_value=(True, "complete")):
                with self.assertRaises(ContractError) as error:
                    client.exec(["python3", "-c", "print('ordinary')"])
            self.assertEqual(error.exception.code, "ARCHARM_COMMAND_OUTPUT_LIMIT")
            self.assertEqual(capture.call_args.args[-1], 8 * 1024 * 1024)
            self.assertNotIsInstance(capture.call_args.args[1][1], process._InventoryStderr)

    def test_only_exact_root_scanner_gets_the_inventory_bound(self):
        scanner = inventory.scanner_argv(family="pacman")
        with self.client() as client, patch.object(process.subprocess, "Popen") as spawn:
            for argv, kwargs in ((["python3", "-c", "print('other')"], {}),
                                 (scanner, {"user": self.lease.user}),
                                 (scanner, {"env": {"LANG": "C"}}),
                                 (scanner, {"output_limit": inventory.MAX_STDOUT_BYTES + 1})):
                options = {"output_limit": inventory.MAX_STDOUT_BYTES, **kwargs}
                with self.subTest(options=tuple(options)), self.assertRaises(ContractError) as error:
                    client._exec_with_capture(argv, **options)
                self.assertEqual(error.exception.code, "ARCHARM_INVENTORY_COMMAND")
            spawn.assert_not_called()
        self.assertNotIn("output_limit", inspect.signature(sdk.ArchArmClient.exec).parameters)

    def test_inventory_protocol_bounds_are_not_expanded(self):
        self.assertEqual(inventory.MAX_STDOUT_BYTES, 32 * 1024 * 1024)
        self.assertEqual(inventory.MAX_ENTRIES, 200000)
        self.assertEqual(inventory.MAX_TOTAL_HASHED_BYTES, 4 * 1024 * 1024 * 1024)
        self.assertEqual(sdk.MAX_WORKER_OUTPUT, 8 * 1024 * 1024)
        self.assertEqual(process.MAX_CAPTURE_BYTES, inventory.MAX_STDOUT_BYTES)

    def test_inventory_stderr_is_limited_to_the_existing_diagnostic_grammar(self):
        for size, outcome in ((4096, "data"), (4097, "overflow")):
            stream = process._InventoryStderr()
            with self.subTest(size=size), patch.object(process.bp.os, "read", return_value=b"x" * size) as read:
                self.assertEqual(stream.read(99, inventory.MAX_STDOUT_BYTES), outcome)
            self.assertEqual(read.call_args.args[1], 4097)
            self.assertEqual(len(stream.data), size)


class RealPipeCaptureTests(unittest.TestCase):
    def child(self, stdout, stderr):
        self.stop_results = []
        real_stop = process.bp._stop

        def record_stop(child):
            result = real_stop(child)
            self.stop_results.append(result)
            return result

        script = ("import os; chunk=b'x'*65536; "
                  "exec('for fd,n in ((1," + str(stdout) + "),(2," + str(stderr) + ")):\\n"
                  " while n:\\n  written=os.write(fd,chunk[:min(n,len(chunk))]); n-=written')")
        with patch.object(process.bp, "_stop", side_effect=record_stop):
            return process.capture([sys.executable, "-I", "-B", "-c", script],
                                   cwd=None, env={}, timeout=10, limit=inventory.MAX_STDOUT_BYTES)

    def test_real_stdout_above_eight_mib_completes(self):
        result = self.child(9 * 1024 * 1024, 0)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"x" * (9 * 1024 * 1024))
        self.assertEqual(result.stderr, b"")
        self.assertEqual(self.stop_results, [])

    def test_real_stdout_above_inventory_bound_stops_and_reaps(self):
        with self.assertRaises(ContractError) as error:
            self.child(inventory.MAX_STDOUT_BYTES + 1, 0)
        self.assertEqual(error.exception.code, "ARCHARM_COMMAND_OUTPUT_LIMIT")
        self.assertEqual(len(self.stop_results), 1)
        self.assertTrue(self.stop_results[0][0])

    def test_real_stderr_above_four_kib_stops_and_reaps(self):
        with self.assertRaises(ContractError) as error:
            self.child(0, 4097)
        self.assertEqual(error.exception.code, "ARCHARM_COMMAND_OUTPUT_LIMIT")
        self.assertEqual(len(self.stop_results), 1)
        self.assertTrue(self.stop_results[0][0])
