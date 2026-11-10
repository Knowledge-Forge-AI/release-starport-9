"""Real timeout exception path with a fixture subprocess boundary, no Docker execution."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9 import hosted_deb as hd
from rs9.build_native import APT_ACTIVITY_DIAGNOSTIC_PREFIX, SubprocessRunner
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.errors import ContractError, safe_details
from rs9.hosted_custody import diagnostic_bytes
from rs9.release_core import digest
from rs9.scratch import canonical


class PreparationDiagnosticsTests(unittest.TestCase):
    def timeout_details(self, command, output, *, stderr=b"private-stderr"):
        runner = SubprocessRunner(timeout=600)
        runner.which = lambda tool: "/usr/bin/" + tool

        def run(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=output, stderr=stderr)

        with patch("rs9.build_native.subprocess.run", side_effect=run):
            with self.assertRaises(ContractError) as caught:
                runner.run(command)
        self.assertEqual(caught.exception.code, "TOOL_TIMEOUT")
        return caught.exception.details

    def provision_timeout_details(self, output):
        runner = SubprocessRunner(timeout=600)
        runner.which = lambda tool: "/usr/bin/" + tool
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            if command[1] == "run":
                raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=output, stderr=b"private-stderr")
            return subprocess.CompletedProcess(command, 0, b"", b"")

        rows = []
        with patch("rs9.build_native.subprocess.run", side_effect=run):
            with self.assertRaises(ContractError) as caught:
                hd.provision_image(
                    runner, "apt", "fixture", "linux/amd64", "phase-owned:fixture", ["python3"],
                    recorder=rows, substage_prefix="client-", apt_activity_diagnostic=True,
                )
        return caught.exception, calls, rows

    def test_current_apt_activity_prefix_labels_timeout_without_raw_output(self):
        error, calls, rows = self.provision_timeout_details(b"Get: https://private.invalid/secret.pkg\n")
        self.assertEqual(error.details["apt_activity"], "fetch")
        self.assertNotIn("private.invalid", repr(error.details))
        self.assertNotIn(b"secret.pkg", repr(error.details).encode())
        self.assertEqual(error.details["deadline_seconds"], 600)
        self.assertEqual(error.details["stderr_sha256"], digest(b"private-stderr"))
        self.assertEqual(len(calls), 2)  # failed provision plus bounded cleanup
        self.assertEqual(rows[0]["outcome"], "timeout")

    def test_apt_activity_labels_and_last_recognized_ordering(self):
        command = ["docker", "run", "--name", "fixture", "image", "sh", "-c",
                   APT_ACTIVITY_DIAGNOSTIC_PREFIX + "apt-get update"]
        markers = (
            (b"Hit: private", "index-hit"),
            (b"Get: private", "fetch"),
            (b"Ign: private", "fetch-ignored"),
            (b"Fetched private", "fetched"),
            (b"Reading package lists: private", "package-lists"),
            (b"Building dependency tree: private", "dependency-tree"),
            (b"Reading state information: private", "state-information"),
            (b"Need to get private", "download-plan"),
            (b"Selecting previously unselected package private", "select"),
            (b"Unpacking private", "unpack"),
            (b"Setting up private", "configure"),
            (b"Processing triggers for private", "triggers"),
        )
        for line, label in markers:
            with self.subTest(label=label):
                self.assertEqual(self.timeout_details(command, line + b"\n")["apt_activity"], label)
        ordered = b"\n".join(line for line, _ in markers[:4]) + b"\nnot an APT line\n" + markers[7][0] + b"\n"
        self.assertEqual(self.timeout_details(command, ordered)["apt_activity"], "download-plan")

    def test_apt_activity_binary_tail_partial_line_and_unknown_are_bounded(self):
        command = ["docker", "run", "--name", "fixture", "image", "sh", "-c",
                   APT_ACTIVITY_DIAGNOSTIC_PREFIX + "apt-get update"]
        clipped = b"Get: stale\n" + (b"x" * 32768) + b"\nFetched final https://private.invalid/pkg\n"
        details = self.timeout_details(command, clipped)
        self.assertEqual(details["apt_activity"], "fetched")
        self.assertNotIn("private.invalid", repr(details))
        boundary_aligned = b"\nGet: retained\n" + (b"x" * 32754)
        self.assertEqual(self.timeout_details(command, boundary_aligned)["apt_activity"], "unknown")
        self.assertEqual(self.timeout_details(command, b"\xff\xfe\nHit: binary\n")["apt_activity"], "index-hit")
        self.assertEqual(self.timeout_details(command, None)["apt_activity"], "unknown")
        self.assertEqual(self.timeout_details(command, "Reading package lists: private\n")["apt_activity"], "package-lists")

    def test_apt_activity_only_applies_to_tagged_docker_run_timeouts(self):
        tagged = APT_ACTIVITY_DIAGNOSTIC_PREFIX + "apt-get update"
        commands = (
            ["docker", "run", "image", "sh", "-c", "apt-get update"],
            ["docker", "exec", "fixture", "sh", "-c", tagged],
            ["podman", "run", "image", "sh", "-c", tagged],
            ["docker", "run", "image", "bash", "-c", tagged],
        )
        for command in commands:
            with self.subTest(command=command[:2]):
                self.assertNotIn("apt_activity", self.timeout_details(command, b"Get: private\n"))

    def test_apt_activity_success_oserror_and_safe_details_are_unchanged_or_closed(self):
        command = ["docker", "run", "image", "sh", "-c", APT_ACTIVITY_DIAGNOSTIC_PREFIX + "apt-get update"]
        runner = SubprocessRunner(timeout=600)
        runner.which = lambda tool: "/usr/bin/" + tool
        with patch("rs9.build_native.subprocess.run", return_value=subprocess.CompletedProcess(command, 0, b"Get: private\n", b"")):
            receipt = runner.run(command)
        self.assertEqual(receipt.exit_code, 0)
        with patch("rs9.build_native.subprocess.run", side_effect=OSError("private")):
            with self.assertRaises(ContractError) as caught:
                runner.run(command)
        self.assertEqual(caught.exception.code, "TOOL_EXECUTION")
        self.assertNotIn("apt_activity", caught.exception.details)
        for value in (None, 1, True, "Get: private", "../fetch", "fetch\n"):
            with self.subTest(value=value):
                sanitized = safe_details({"apt_activity": value})
                self.assertNotIn("apt_activity", sanitized)
                self.assertTrue(sanitized["details_truncated"])

    def test_apt_activity_opt_in_prefix_preserves_default_script_and_rejects_non_apt_before_mutation(self):
        runner = SubprocessRunner(timeout=600)
        runner.which = lambda tool: "/usr/bin/" + tool
        scripts = []

        def run(command, **kwargs):
            if command[1] == "run":
                scripts.append(command[-1])
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with patch("rs9.build_native.subprocess.run", side_effect=run):
            hd.provision_image(runner, "apt", "fixture", "linux/amd64", "default:fixture", ["python3"])
            hd.provision_image(runner, "apt", "fixture", "linux/amd64", "current:fixture", ["python3"],
                               apt_activity_diagnostic=True)
            with self.assertRaises(ContractError) as caught:
                hd.provision_image(runner, "dnf", "fixture", "linux/amd64", "wrong:fixture", ["python3"],
                                   apt_activity_diagnostic=True)
        self.assertEqual(caught.exception.code, "INVALID_ARGUMENT")
        self.assertEqual(len(scripts), 2)
        self.assertEqual(scripts[1].removeprefix(APT_ACTIVITY_DIAGNOSTIC_PREFIX), scripts[0])

    def test_execute_deb_selects_opt_in_only_for_current_generation(self):
        selected = []

        for generation in (HISTORICAL_GENERATION, CURRENT_GENERATION):
            with self.subTest(generation=generation):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                root = Path(temporary.name)
                scratch = root / "scratch"
                scratch.mkdir()
                runner = SubprocessRunner(timeout=600)
                runner.which = lambda tool: "/usr/bin/" + tool
                calls = []

                def run(command, **kwargs):
                    calls.append(command)
                    if command[1] == "run":
                        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b"Get: synthetic\n", stderr=b"private")
                    return subprocess.CompletedProcess(command, 0, b"", b"")

                with patch.object(hd, "prepare_environment", return_value={"image_ref": "fixture", "unpinned": False}), \
                     patch("rs9.build_native.subprocess.run", side_effect=run):
                    result = hd.execute_deb({
                        "repository": root, "scratch": scratch, "system": "amd64", "pins": {},
                        "runner": runner, "generation": generation,
                        "maintainer": "fixture-maintainer",
                    })
                gate = next(g for g in result["gates"] if g["name"] == "deb-container-environment")
                self.assertEqual(gate["reason"], "TOOL_TIMEOUT")
                script = next(command[-1] for command in calls if command[1] == "run")
                selected.append(script.startswith(APT_ACTIVITY_DIAGNOSTIC_PREFIX))
                if generation == CURRENT_GENERATION:
                    self.assertEqual(gate["details"]["apt_activity"], "fetch")
                else:
                    self.assertNotIn("apt_activity", gate["details"])
        self.assertEqual(selected, [False, True])

    def test_pages_client_selects_opt_in_only_for_current_generation(self):
        selected = []

        for generation in (HISTORICAL_GENERATION, CURRENT_GENERATION):
            with self.subTest(generation=generation):
                temporary = tempfile.TemporaryDirectory()
                self.addCleanup(temporary.cleanup)
                root = Path(temporary.name)
                scratch = root / "scratch"
                scratch.mkdir()
                tree = root / "tree"
                tree.mkdir()
                runner = SubprocessRunner(timeout=600)
                runner.which = lambda tool: "/usr/bin/" + tool
                host = hd.RecordingRunner(runner)
                calls = []

                def run(command, **kwargs):
                    calls.append(command)
                    if command[1] == "run":
                        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b"Get: synthetic\n", stderr=b"private")
                    return subprocess.CompletedProcess(command, 0, b"", b"")

                context = {
                    "generation": generation,
                    "pins": {},
                    "wrong_signing_fixture": object(),
                }
                bundles = {("deb", "amd64"): {"packages": {}}}
                gates, details = [], {}
                with patch.object(hd, "prepare_environment", return_value={"image_ref": "fixture"}), \
                     patch("rs9.build_native.subprocess.run", side_effect=run):
                    hd._pages_client_tests(
                        context, host, root, scratch, {}, tree, bundles, object(), gates, details, [], [], "fixture-rpm",
                    )
                script = next(command[-1] for command in calls if command[1] == "run")
                selected.append(script.startswith(APT_ACTIVITY_DIAGNOSTIC_PREFIX))
                setup = next(g for g in gates if g["name"] == "pages-client.setup")
                if generation == CURRENT_GENERATION:
                    self.assertEqual(setup["details"]["apt_activity"], "fetch")
                else:
                    self.assertNotIn("apt_activity", setup["details"])
        self.assertEqual(selected, [False, True])

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
