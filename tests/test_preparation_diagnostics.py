"""Real timeout exception path with a fixture subprocess boundary, no Docker execution."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from rs9 import hosted_deb as hd
from rs9 import hosted_packaging as hp
from rs9.build_native import APT_ACTIVITY_DIAGNOSTIC_PREFIX, SubprocessRunner
from rs9.current_generation import CURRENT_GENERATION, HISTORICAL_GENERATION
from rs9.errors import ContractError, safe_details
from rs9.hosted_custody import diagnostic_bytes
from rs9.release_core import digest
from rs9.scratch import canonical


class PreparationDiagnosticsTests(unittest.TestCase):
    def test_pacman_full_upgrade_routing_is_current_only_static(self):
        hosted_source = Path(hp.__file__).read_text(encoding="utf-8")
        deb_source = Path(hd.__file__).read_text(encoding="utf-8")
        self.assertEqual(hosted_source.count('"pacman_full_upgrade": True'), 2)
        self.assertEqual(hosted_source.count('if family == "pacman" and generation == CURRENT_GENERATION else {}'), 2)
        self.assertIn('"pacman_failure_diagnostic": True, "pacman_full_upgrade": True, "substage_prefix": "build-"', hosted_source)
        self.assertIn('"pacman_failure_diagnostic": True, "pacman_full_upgrade": True, "substage_prefix": "client-"', hosted_source)
        self.assertIn('if context.get("generation", HISTORICAL_GENERATION) == CURRENT_GENERATION else {}', deb_source)
        self.assertIn('"pacman_full_upgrade": True', deb_source)

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

    def test_apt_fetch_real_description_forms_and_provision_timeout_boundary(self):
        cases = (
            (b"Get:1 http://archive.ubuntu.com/ubuntu resolute InRelease\n",
             {"origin": "archive", "suite": "resolute", "kind": "inrelease"}),
            (b"Get:2 https://security.ubuntu.com/ubuntu/ resolute-security/main amd64 Packages [1,234 kB]\n",
             {"origin": "security", "suite": "resolute-security", "kind": "packages",
              "component": "main", "architecture": "amd64"}),
            (b"Get:3 http://ports.ubuntu.com/ubuntu-ports resolute-updates/universe arm64 libdemo arm64 1.2.3-4 [32 kB]\n",
             {"origin": "ports", "suite": "resolute-updates", "kind": "package",
              "component": "universe", "index_architecture": "arm64", "package_architecture": "arm64", "package": "libdemo"}),
            (b"Get:4 http://archive.ubuntu.com/ubuntu resolute/main amd64 python3-pkg-resources all 1:68.1.2-2ubuntu1 [168 kB]\n",
             {"origin": "archive", "suite": "resolute", "kind": "package", "component": "main",
              "index_architecture": "amd64", "package_architecture": "all", "package": "python3-pkg-resources"}),
        )
        for line, expected in cases:
            with self.subTest(expected=expected):
                error, calls, rows = self.provision_timeout_details(line)
                self.assertEqual(error.code, "TOOL_TIMEOUT")
                self.assertEqual(error.details["apt_fetch"], expected)
                self.assertEqual(rows[0]["apt_fetch"], expected)
                self.assertEqual(error.details["apt_activity"], "fetch")
                self.assertEqual(error.details["deadline_seconds"], 600)
                self.assertEqual(error.details["stdout_sha256"], digest(line))
                self.assertEqual(error.details["stderr_sha256"], digest(b"private-stderr"))
                self.assertEqual(error.details["cleanup"], "complete")
                self.assertEqual(rows[0]["outcome"], "timeout")
                self.assertEqual(len(calls), 2)
                for withheld in ("archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com", "/ubuntu",
                                 "1.2.3-4", "68.1.2-2ubuntu1", "1,234 kB", "32 kB", "168 kB"):
                    self.assertNotIn(withheld, repr(error.details))

    def test_apt_fetch_rejects_nonofficial_unknown_and_nonpackage_index_records(self):
        lines = (
            b"Get:1 https://user:pass@archive.ubuntu.com/ubuntu resolute InRelease\n",
            b"Get:1 https://archive.ubuntu.com:443/ubuntu resolute InRelease\n",
            b"Get:1 https://mirror.archive.ubuntu.com/ubuntu resolute InRelease\n",
            b"Get:1 https://archive.ubuntu.com/%75buntu resolute InRelease\n",
            b"Get:1 https://archive.ubuntu.com/notubuntu resolute InRelease\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu/private resolute InRelease\n",
            b"Get:1 https://ports.ubuntu.com/ubuntu-ports/pool/x resolute InRelease\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu?token=private resolute InRelease\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu#private resolute InRelease\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu resolute InRelease [1 secret]\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu noble InRelease\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu resolute/unknown amd64 Packages\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu resolute/main riscv64 Packages\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu resolute/main all Packages\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu resolute/main amd64 X-Package amd64 1.0\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu resolute/main amd64 libdemo Metadata\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu resolute/main amd64 c-n-f Metadata [8,968 B]\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu resolute/main amd64 Components\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu resolute/main Translation-en\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu resolute/main amd64 Packages 2026.11.pdiff\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu resolute/main amd64 c-n-f amd64 Metadata\n",
            b"Get:1 https://archive.ubuntu.com/ubuntu resolute/main amd64 libdemo 1.2.3-4\n",
        )
        for line in lines:
            with self.subTest(line=line):
                error, _, _ = self.provision_timeout_details(line)
                self.assertEqual(error.details["apt_activity"], "fetch")
                self.assertNotIn("apt_fetch", error.details)

    def test_apt_fetch_binds_final_activity_and_keeps_clipping_and_failure_guards(self):
        first = b"Get:1 http://archive.ubuntu.com/ubuntu resolute InRelease\n"
        last = b"Get:8 http://archive.ubuntu.com/ubuntu resolute/main amd64 libdemo all 1.2.3-4\n"
        expected = {"origin": "archive", "suite": "resolute", "kind": "package", "component": "main",
                    "index_architecture": "amd64", "package_architecture": "all", "package": "libdemo"}
        for output in (first + last, first + b"x" * 32768 + b"\n\xff\xfe\n" + last):
            error, _, _ = self.provision_timeout_details(output)
            self.assertEqual(error.details["apt_fetch"], expected)
            self.assertEqual(error.details["apt_activity"], "fetch")
            self.assertNotIn("1.2.3-4", repr(error.details))
        later = (
            b"Get:9 https://unknown.invalid/ubuntu resolute InRelease\n",
            b"Get:9 http://archive.ubuntu.com/ubuntu resolute/main Translation-en\n",
            b"Hit:9 http://archive.ubuntu.com/ubuntu resolute InRelease\n",
            b"Ign:9 http://archive.ubuntu.com/ubuntu resolute InRelease\n",
            b"Unpacking something\n",
            b"Err:9 transport failed\n",
        )
        for line in later:
            with self.subTest(later=line):
                error, _, _ = self.provision_timeout_details(first + last + line)
                self.assertNotIn("apt_fetch", error.details)
        boundary = b"\n" + last + b"x" * (32768 - len(last))
        boundary_error, _, _ = self.provision_timeout_details(boundary)
        self.assertNotIn("apt_fetch", boundary_error.details)
        with patch("rs9.build_native._apt_fetch_for_timeout", side_effect=RuntimeError("private parser failure")):
            error, _, rows = self.provision_timeout_details(last)
        self.assertEqual(error.code, "TOOL_TIMEOUT")
        self.assertEqual(error.details["stdout_sha256"], digest(last))
        self.assertEqual(error.details["stderr_sha256"], digest(b"private-stderr"))
        self.assertEqual(error.details["cleanup"], "complete")
        self.assertNotIn("apt_fetch", error.details)
        self.assertEqual(rows[0]["outcome"], "timeout")

    def test_apt_fetch_sanitizer_rejects_wrong_nested_shapes_and_credential_like_names(self):
        class DictionarySubclass(dict):
            pass
        valid = {"origin": "archive", "suite": "resolute", "kind": "package", "component": "main",
                 "index_architecture": "amd64", "package_architecture": "all", "package": "libdemo"}
        sanitized = safe_details({"apt_fetch": valid})["apt_fetch"]
        self.assertEqual(sanitized, valid)
        self.assertIsNot(sanitized, valid)
        invalid = (None, [], "descriptor", 1, DictionarySubclass(valid),
            {**valid, 1: "bad-key"}, {**valid, "extra": "ignored"},
            {**valid, "origin": "evil"}, {**valid, "suite": "noble"},
            {**valid, "index_architecture": "all"}, {**valid, "package_architecture": "riscv64"},
            {**valid, "package": "Bad_Name"}, {**valid, "package": "../private"},
            {**valid, "package": 1}, {**valid, "package": "p"}, {**valid, "package": "a" * 40},
            {**valid, "version": "secret"},
            {"origin": "archive", "suite": "resolute", "kind": "inrelease", "package": "bad"},
            {"origin": "archive", "suite": "resolute", "kind": "packages", "component": "main", "architecture": "all"})
        for value in invalid:
            with self.subTest(value=value):
                result = safe_details({"apt_fetch": value})
                self.assertNotIn("apt_fetch", result)
                self.assertTrue(result["details_truncated"])
        with patch("rs9.security.scan_for_credentials", side_effect=ContractError("CREDENTIAL_DETECTED", "Synthetic refusal")):
            self.assertNotIn("apt_fetch", safe_details({"apt_fetch": valid}))

    def test_apt_fetch_unmarked_success_and_oserror_routes_are_unchanged(self):
        valid = b"Get:1 https://archive.ubuntu.com/ubuntu resolute InRelease\n"
        tagged = APT_ACTIVITY_DIAGNOSTIC_PREFIX + "apt-get update"
        commands = (["docker", "run", "image", "sh", "-c", "apt-get update"],
                    ["docker", "exec", "fixture", "sh", "-c", tagged],
                    ["podman", "run", "image", "sh", "-c", tagged],
                    ["docker", "run", "image", "bash", "-c", tagged])
        for command in commands:
            self.assertNotIn("apt_fetch", self.timeout_details(command, valid))
        command = ["docker", "run", "image", "sh", "-c", tagged]
        runner = SubprocessRunner(timeout=600)
        runner.which = lambda tool: "/usr/bin/" + tool
        with patch("rs9.build_native.subprocess.run", return_value=subprocess.CompletedProcess(command, 0, valid, b"")):
            receipt = runner.run(command)
        self.assertEqual(receipt.exit_code, 0)
        self.assertNotIn("apt_fetch", receipt.to_record())
        with patch("rs9.build_native.subprocess.run", side_effect=OSError("private")):
            with self.assertRaises(ContractError) as caught:
                runner.run(command)
        self.assertEqual(caught.exception.code, "TOOL_EXECUTION")
        self.assertNotIn("apt_fetch", caught.exception.details)

    def test_apt_fetch_crlf_bytearray_and_string_timeout_streams(self):
        data = b"Get:1 https://archive.ubuntu.com/ubuntu resolute InRelease\r\n"
        for value in (data, bytearray(data), data.decode()):
            with self.subTest(kind=type(value).__name__):
                error, _, _ = self.provision_timeout_details(value)
                self.assertEqual(error.details["apt_fetch"], {"origin": "archive", "suite": "resolute", "kind": "inrelease"})
                self.assertEqual(error.details["stdout_sha256"], digest(data))

    def test_apt_fetch_current_debian_gate_and_actual_recording_keep_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scratch = root / "scratch"
            scratch.mkdir()
            line = b"Get:1 http://archive.ubuntu.com/ubuntu resolute/main amd64 libdemo all 1.2\n"
            expected = {"origin": "archive", "suite": "resolute", "kind": "package", "component": "main",
                        "index_architecture": "amd64", "package_architecture": "all", "package": "libdemo"}
            runner = SubprocessRunner(timeout=600)
            runner.which = lambda tool: "/usr/bin/" + tool
            def run(command, **kwargs):
                if command[1] == "run":
                    raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=line, stderr=b"")
                return subprocess.CompletedProcess(command, 0, b"", b"")
            with patch.object(hd, "prepare_environment", return_value={"image_ref": "fixture", "unpinned": False}), \
                 patch("rs9.build_native.subprocess.run", side_effect=run):
                result = hd.execute_deb({"repository": root, "scratch": scratch, "system": "amd64", "pins": {},
                    "runner": runner, "generation": CURRENT_GENERATION, "maintainer": "fixture-maintainer"})
            gate = next(g for g in result["gates"] if g["name"] == "deb-container-environment")
            self.assertEqual((gate["status"], gate["reason"]), ("fail", "TOOL_TIMEOUT"))
            rows = result["details"]["container_preparation"]
            timeout = next(row for row in rows if row.get("outcome") == "timeout")
            values = (gate["apt_fetch"], gate["details"]["apt_fetch"], timeout["apt_fetch"],
                      result["details"]["environment_failure"]["details"]["apt_fetch"])
            self.assertTrue(all(value == expected for value in values))
            self.assertEqual(gate["details"]["cleanup"], "complete")

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
