"""Real timeout exception path with a fixture subprocess boundary, no Docker execution."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9 import hosted_deb as hd
from rs9.build_native import SubprocessRunner
from rs9.errors import ContractError
from rs9.hosted_custody import diagnostic_bytes
from rs9.release_core import digest
from rs9.scratch import canonical


class PreparationDiagnosticsTests(unittest.TestCase):
    def test_cleanup_deadline_is_local_bounded_and_reentrant(self):
        for timeout in (None, 600, 5):
            with self.subTest(timeout=timeout):
                runner=SubprocessRunner(timeout=timeout)
                runner.which=lambda tool:"/usr/bin/"+tool
                host=hd.RecordingRunner(runner)
                calls=[]
                def run(command, **kwargs):
                    calls.append((command[-1],kwargs["timeout"]))
                    self.assertEqual(runner.timeout,timeout)
                    if command[-1]=="outer":
                        self.assertEqual(hd._cleanup_step(host,host,["docker","rm","-f","inner"]),"complete")
                        host.run(["docker","image","inspect","ordinary"])
                    return subprocess.CompletedProcess(command,0,b"",b"")
                with patch("rs9.build_native.subprocess.run",side_effect=run):
                    self.assertEqual(hd._cleanup_step(host,host,["docker","rm","-f","outer"]),"complete")
                limit=30 if timeout is None else min(timeout,30)
                self.assertEqual(calls,[("outer",limit),("inner",limit),("ordinary",timeout)])
                self.assertEqual(runner.timeout,timeout)
                self.assertEqual(len(host.receipts),3)
                self.assertEqual([r["deadline_seconds"] for r in host.preparation],[limit,limit])

    def test_cleanup_timeout_keeps_original_runner_and_records_failure(self):
        runner,_,_=self.fixture(None)
        runner.timeout=None
        rows=[]
        def run(command,**kwargs):
            self.assertIsNone(runner.timeout)
            raise subprocess.TimeoutExpired(command,kwargs["timeout"],output=b"cleanup-output",stderr=b"cleanup-error")
        with patch("rs9.build_native.subprocess.run",side_effect=run):
            self.assertEqual(hd._cleanup_step(runner,rows,["docker","rm","-f","owned"]),"failed")
        self.assertIsNone(runner.timeout)
        self.assertEqual(rows[0]["deadline_seconds"],30)
        self.assertEqual(rows[0]["code"],"TOOL_TIMEOUT")
        self.assertEqual(rows[0]["stderr_sha256"],digest(b"cleanup-error"))

    def fixture(self, boundary, *, cleanup_timeout=False):
        calls=[]
        def run(command,**kwargs):
            if command[1]=="pull":stage="pull"
            elif command[1:3]==["image","inspect"]:stage="inspect"
            elif command[1]=="commit":stage="commit"
            elif command[1] in ("rm","rmi"):stage="cleanup"
            elif "cat /etc/os-release" in " ".join(command):stage="release-probe"
            elif "--name" in command and command[command.index("--name")+1].startswith("rs9-tool-"):stage="container-tool"
            elif "--name" in command:stage="provision"
            else:stage="container-tool"
            calls.append((stage,command,kwargs["timeout"]))
            if stage==boundary or (cleanup_timeout and stage=="cleanup"):
                raise subprocess.TimeoutExpired(command,kwargs["timeout"],output=b"partial-output",stderr=b"partial-error")
            out=(b"ubuntu@sha256:"+b"a"*64+b"|amd64\n" if stage=="inspect" else
                 b'VERSION_ID="26.04"\nVERSION_CODENAME=resolute\namd64\n' if stage=="release-probe" else b"tool 1.0\n")
            return subprocess.CompletedProcess(command,0,out,b"")
        runner=SubprocessRunner(timeout=600)
        runner.which=lambda tool:"/usr/bin/"+tool
        return runner,run,calls

    def test_environment_boundaries_preserve_real_timeouts_and_gate_details(self):
        for boundary,expected in (("pull","pull"),("inspect","inspect"),("release-probe","release-probe"),
                                  ("provision","build-provision"),("commit","build-commit"),
                                  ("container-tool","container-tool")):
            with self.subTest(boundary=boundary),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve();scratch=root/"scratch";scratch.mkdir()
                runner,run,calls=self.fixture(boundary,cleanup_timeout=boundary=="release-probe")
                with patch("rs9.build_native.subprocess.run",side_effect=run):
                    result=hd.execute_deb({"repository":root,"scratch":scratch,"system":"amd64", "pins":{},"runner":runner})
                gate=next(g for g in result["gates"] if g["name"]=="deb-container-environment")
                self.assertEqual(gate["reason"],"TOOL_TIMEOUT")
                self.assertEqual(gate["details"]["substage"],expected)
                self.assertEqual(gate["details"]["tool"], "docker")
                self.assertEqual(gate["details"]["deadline_seconds"],600)
                self.assertEqual(gate["details"]["stdout_sha256"],digest(b"partial-output"))
                self.assertEqual(gate["details"]["stderr_sha256"],digest(b"partial-error"))
                failure=result["details"]["environment_failure"]
                self.assertEqual(failure["code"],"TOOL_TIMEOUT")
                rows=result["details"]["container_preparation"]
                failed=next(r for r in rows if r["substage"]==expected and r["outcome"]=="timeout")
                self.assertEqual(failed["stdout_sha256"],gate["details"]["stdout_sha256"])
                self.assertIsInstance(failed["elapsed_ms"],int)
                self.assertTrue(all(c[2]<=30 for c in calls if c[0]=="cleanup"))
                self.assertEqual(runner.timeout,600)
                for name in ("deb-package-build","deb-shlibdeps-closure","deb-client-qualification"):
                    self.assertEqual(next(g for g in result["gates"] if g["name"]==name)["status"],"not-run")
                diagnostic=root/"preparation.json";diagnostic.write_bytes(canonical(result["details"]))
                diagnostic_bytes(diagnostic) # Real custody scanner accepts bounded diagnostic.
                self.assertNotIn(str(root),diagnostic.read_text())
                if boundary=="release-probe":
                    release=next(c[1] for c in calls if c[0]=="release-probe")
                    cleanup=next(c[1] for c in calls if c[0]=="cleanup")
                    self.assertEqual(cleanup[-1],release[release.index("--name")+1])
                    self.assertEqual(failure["details"]["cleanup"],"failed")
                if boundary == "container-tool":
                    command = next(c[1] for c in calls if c[0] == "container-tool")
                    name = command[command.index("--name")+1]
                    self.assertNotIn("--rm", command)
                    self.assertTrue(any(c[1] == ["docker", "rm", "-f", name] for c in calls))
                    self.assertEqual(failure["details"]["cleanup"], "complete")

    def test_client_boundaries_and_successful_preparation_recorded(self):
        for boundary in ("provision","commit",None):
            with self.subTest(boundary=boundary):
                runner,run,calls=self.fixture(boundary)
                rows=[]
                with patch("rs9.build_native.subprocess.run",side_effect=run):
                    if boundary:
                        with self.assertRaises(ContractError) as caught:
                            hd.provision_image(runner,"apt","fixture","linux/amd64","phase-owned:fixture",["python3"],
                                               recorder=rows,substage_prefix="client-")
                        self.assertEqual(caught.exception.code,"TOOL_TIMEOUT")
                        self.assertEqual(caught.exception.details["substage"],"client-"+boundary)
                    else:
                        hd.prepare_environment(runner,"amd64",{},recorder=rows)
                        hd.provision_image(runner,"apt","fixture","linux/amd64","phase-owned:fixture",["python3"],
                                           recorder=rows,substage_prefix="client-")
                for row in rows:
                    self.assertIn("elapsed_ms",row)
                    self.assertIn("deadline_seconds",row)
                    self.assertEqual(row["tool"],"docker")
                    self.assertIn("stdout_sha256",row)
                    self.assertIn("stderr_sha256",row)
                self.assertEqual(runner.timeout,600)
                self.assertEqual(sum(stage=="provision" for stage,cmd,deadline in calls),1)
