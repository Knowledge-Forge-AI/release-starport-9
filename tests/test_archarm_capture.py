"""SDK capture/guard composition with no actual process or native tool."""
import subprocess
import unittest
from unittest.mock import patch, Mock
from rs9._archarm_support import process
from rs9._archarm_support.docker import bounded_runner
from rs9.build_native import SubprocessRunner
from rs9.hosted_deb import RecordingRunner
from rs9.errors import ContractError
from rs9 import archarm_sdk as sdk


class Leaf(SubprocessRunner):
    def which(self, tool):
        return "/usr/bin/" + tool


class DuckGuard:
    def __init__(self, inner):
        self.inner = inner
        self.calls = []
    def which(self, tool):
        return self.inner.which(tool)
    def run(self, argv, **kwargs):
        if argv == ["forbidden"]:
            raise ContractError("GUARD_REFUSED","guard retained")
        self.calls.append(list(argv))
        return self.inner.run(argv,**kwargs)


class CaptureTests(unittest.TestCase):
    def fake(self, termination="exited", *, complete=True, wait_timeout=False):
        child=Mock()
        child.returncode=0
        child.stdout=Mock()
        child.stderr=Mock()
        if wait_timeout:
            child.wait.side_effect=subprocess.TimeoutExpired(["tool"],1)
        def captured(proc, streams, selector, deadline, limit):
            streams[0].data.extend(b"public stdout")
            streams[1].data.extend(b"public stderr")
            for stream in streams:
                stream.complete=complete
            return termination
        return child,captured

    def run_fake(self, termination="exited", **kwargs):
        child,captured=self.fake(termination,**kwargs)
        with patch.object(process.subprocess,"Popen",return_value=child) as spawn, \
                patch.object(process.bp,"_capture",side_effect=captured), \
                patch.object(process.bp,"_stop",return_value=(True,"complete")) as stop:
            try:
                result=process.capture(["tool"],cwd="/public/build",env={"LANG":"C"},timeout=3,limit=4096)
            except ContractError as error:
                result=error
            child.stdout.close.assert_called_once()
            child.stderr.close.assert_called_once()
            self.assertEqual(spawn.call_args.kwargs["cwd"],"/public/build")
            self.assertEqual(spawn.call_args.kwargs["process_group"],0)
            self.assertEqual(spawn.call_args.kwargs["stdin"],subprocess.DEVNULL)
            return result,stop.call_count

    def test_only_complete_eof_capture_can_return_bytes(self):
        result,stops=self.run_fake()
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b"public stdout",b"public stderr"))
        self.assertEqual(stops,0)

    def test_overflow_deadline_capture_error_and_incomplete_eof_refuse(self):
        for termination,complete,code in (
                ("overflow",False,"ARCHARM_COMMAND_OUTPUT_LIMIT"),
                ("deadline",False,"TOOL_TIMEOUT"),
                ("capture-error",False,"ARCHARM_CAPTURE_FAILED"),
                ("exited",False,"ARCHARM_CAPTURE_FAILED")):
            result,stops=self.run_fake(termination,complete=complete)
            with self.subTest(termination=termination):
                self.assertIsInstance(result,ContractError)
                self.assertEqual(result.code,code)
                self.assertNotIn("public stdout",str(result))
                self.assertEqual(stops,0 if termination=="exited" else 1)

    def test_wait_timeout_stops_and_reaps_owned_child(self):
        result,stops=self.run_fake(wait_timeout=True)
        self.assertEqual(result.code,"TOOL_TIMEOUT")
        self.assertEqual(stops,1)

    def test_invalid_bounds_never_spawn(self):
        for timeout,limit in ((0,1),(5401,1),(True,1),(float("nan"),1),(1,0),(1,True),(1,8388609)):
            with self.subTest(timeout=timeout,limit=limit),patch.object(process.subprocess,"Popen") as spawn:
                with self.assertRaises(ContractError):
                    process.capture(["tool"],cwd=None,env={},timeout=timeout,limit=limit)
                spawn.assert_not_called()

    def test_guard_and_recording_wrappers_survive_bounded_leaf_copy(self):
        leaf=Leaf(timeout=600)
        guard=DuckGuard(leaf)
        host=RecordingRunner(guard)
        bounded=bounded_runner(host,30,8192)
        with patch.object(process,"capture",return_value=process.Capture(0,b"ok",b"")) as capture:
            with self.assertRaises(ContractError) as error:
                bounded.run(["forbidden"])
            self.assertEqual(error.exception.code,"GUARD_REFUSED")
            capture.assert_not_called()
            receipt=bounded.run(["gpgv"])
        self.assertEqual(guard.calls,[["gpgv"]])
        self.assertIs(host.receipts[0],receipt)
        self.assertTrue(receipt.executed)
        self.assertEqual(capture.call_args.kwargs["timeout"],30)
        self.assertEqual(capture.call_args.kwargs["limit"],8192)
        self.assertEqual(leaf.timeout,600)
        self.assertFalse(hasattr(leaf,"_archarm_capture_limit"))

    def test_default_runner_keeps_original_subprocess_contract(self):
        with patch("rs9.build_native.subprocess.run",return_value=subprocess.CompletedProcess(["tool"],2,b"old",b"failure")) as run, \
                patch.object(process,"capture",side_effect=AssertionError("SDK-only path")):
            receipt=Leaf(timeout=17).run(["tool"])
        self.assertEqual((receipt.exit_code,receipt.stdout_bytes,receipt.stderr_bytes),(2,b"old",b"failure"))
        self.assertEqual(run.call_args.kwargs["timeout"],17)
        self.assertTrue(run.call_args.kwargs["capture_output"])

    def test_sdk_worker_limits_reach_real_capture_through_both_runner_shapes(self):
        timeouts = {name: value for name, value in vars(sdk).items()
                    if name.endswith("_SECONDS")}
        self.assertEqual(set(timeouts), {"BUILDER_SECONDS", "REPOSITORY_SECONDS", "CLIENT_EXEC_SECONDS"})
        for name, timeout in timeouts.items():
            self.assertGreaterEqual(timeout, 0.001)
            self.assertLessEqual(timeout, 5400)
            for guarded in (False, True):
                with self.subTest(role=name, guarded=guarded):
                    leaf = Leaf(timeout=600)
                    host = RecordingRunner(DuckGuard(leaf) if guarded else leaf)
                    bounded = bounded_runner(host, timeout, sdk.MAX_WORKER_OUTPUT)
                    child, captured = self.fake()
                    with patch.object(process.subprocess, "Popen", return_value=child) as spawn, \
                            patch.object(process.bp, "_capture", side_effect=captured) as capture:
                        receipt = bounded.run(["tool"])
                    spawn.assert_called_once()
                    self.assertEqual(capture.call_args.args[-1], sdk.MAX_WORKER_OUTPUT)
                    self.assertEqual(receipt.stdout_bytes, b"public stdout")
                    self.assertTrue(receipt.executed)
                    self.assertIs(host.receipts[0], receipt)
                    self.assertEqual(leaf.timeout, 600)
                    self.assertFalse(hasattr(leaf, "_archarm_capture_limit"))

    def test_wrapper_cycle_fails_closed(self):
        guard=DuckGuard(Leaf())
        guard.inner=guard
        with self.assertRaises(ContractError) as error:
            bounded_runner(guard,30)
        self.assertEqual(error.exception.code,"ARCHARM_HOST_RUNNER_CHAIN")
