"""Pure failed-provision observation tests; no package commands execute."""
import subprocess
import unittest
from unittest.mock import patch

from rs9 import hosted_deb as hd
from rs9 import provision_observation as po
from rs9.build_native import SubprocessRunner
from rs9.errors import ContractError, safe_details
from rs9.release_core import digest


class ProvisionObservationTests(unittest.TestCase):
    def test_closed_category_examples(self):
        examples = {
            "metadata": b"Failed to download metadata for repo private",
            "mirror": b"All mirrors were tried",
            "dns": b"Could not resolve host: private.invalid",
            "network": b"Failed to connect to https://private.invalid/token",
            "tls": b"SSL certificate problem: certificate verify failed",
            "repo-gpg": b"GPG check FAILED",
            "no-match": b"No match for argument: private-package",
            "disk": b"No space left on device /private/path",
            "oom": b"Cannot allocate memory",
        }
        for category, raw in examples.items():
            with self.subTest(category=category):
                self.assertEqual(po.classify_provision_failure(b"", raw, []), category)
        self.assertEqual(po.classify_provision_failure(b"Killed", b"exit 137", []), "unknown")
        self.assertEqual(po.classify_provision_failure(b"metadata DNS TLS mirror", b"", []), "unknown")
        self.assertEqual(po.classify_provision_failure(examples["disk"], examples["dns"], []), "dns disk")

    def test_pacman_categories_are_opt_in_fixed_ordered_and_bounded(self):
        names = ["pkg" + str(i) for i in range(8)]
        lines = [
            b"failed to download metadata", b"all mirrors were tried", b"could not resolve host",
            b"failed to connect", b"ssl certificate problem", b"gpg check failed",
            *(b"No match for argument: " + name.encode() for name in names),
            b"no space left on device", b"out of memory", b"could not satisfy dependencies",
            b"conflicting files", b"invalid or corrupted package (PGP signature)",
            b"unable to lock database", b"failed to prepare transaction",
            b"error while loading shared libraries", b"bash: pacman: command not found",
        ]
        raw = b"\n".join(lines) + b"\n" + b"x" * po.MAX_STREAM_BYTES
        observed = po.classify_provision_failure(None, raw, names, pacman_failure_diagnostic=True)
        expected = ("metadata mirror dns network tls repo-gpg no-match disk oom dependency file-conflict "
                    "package-corrupt database-lock transaction loader command-missing output-unreadable "
                    "scan-truncated missing:pkg0 missing:pkg1 missing:pkg2 names-omitted")
        self.assertEqual(observed, expected)
        self.assertLessEqual(len(observed), po.MAX_REASON_BYTES)
        self.assertEqual(safe_details({"reason_token": observed}), {"reason_token": observed})

    def test_pacman_categories_are_not_emitted_without_opt_in(self):
        for raw in (
                b"could not satisfy dependencies", b"conflicting files", b"exists in filesystem",
                b"invalid or corrupted database (PGP signature)", b"unable to lock database",
                b"failed to commit transaction", b"symbol lookup error: libx.so",
                b"sh: 1: pacman: not found"):
            with self.subTest(raw=raw):
                self.assertEqual(po.classify_provision_failure(b"", raw, []), "unknown")

    def test_pacman_option_requires_boolean(self):
        for value in (1, None, "true"):
            with self.subTest(value=value), self.assertRaises(ContractError) as caught:
                po.classify_provision_failure(b"", b"", [], pacman_failure_diagnostic=value)
            self.assertEqual(caught.exception.code, "INVALID_ARGUMENT")

    def test_package_names_only_from_source_argument(self):
        examples = (b"No match for argument: safe-devel", b"Unable to find a match: safe-devel unknown",
                    b"E: Unable to locate package safe-devel", b"error: target not found: safe-devel",
                    b"Package 'safe-devel' has no installation candidate", b"No package safe-devel available.")
        for raw in examples:
            with self.subTest(raw=raw):
                self.assertEqual(po.classify_provision_failure(b"", raw, ["safe-devel"]),
                                 "no-match missing:safe-devel")
        self.assertEqual(po.classify_provision_failure(b"", b"No match for argument: safe-devel", []), "no-match")

    def test_untrusted_private_text_and_source_credentials_never_retained(self):
        token = "ghp_" + "A" * 36
        raw = ("No match for argument: " + token + "\nNo match for argument: private-name\n"
               "Unable to find a match: safe-devel https://u:secret@private.invalid/private/path\n"
               "Could not resolve host: https://u:secret@private.invalid/private/path").encode()
        observed = po.classify_provision_failure(raw, b"", ["safe-devel", token, "/private/path"])
        self.assertEqual(observed, "dns no-match missing:safe-devel")
        self.assertEqual(safe_details({"reason_token": observed}), {"reason_token": observed})
        for private in (token, "private-name", "private.invalid", "secret", "/private/path"):
            self.assertNotIn(private, observed)

    def test_caps_and_partial_lines(self):
        names = ["package" + str(i) for i in range(8)]
        raw = ("Unable to find a match: " + " ".join(names)).encode()
        value = po.classify_provision_failure(raw, b"", names)
        self.assertEqual(value.count("missing:"), 4)
        self.assertTrue(value.endswith("names-omitted"))
        self.assertLessEqual(len(value), po.MAX_REASON_BYTES)
        self.assertEqual(safe_details({"reason_token": value})["reason_token"], value)
        # Full stdout cannot starve bounded stderr observations.
        value = po.classify_provision_failure(b"x\n" * 1000, b"No space left on device", [])
        self.assertEqual(value, "disk scan-truncated")
        with patch.object(po, "MAX_STREAM_BYTES", 32):
            raw = b"No match for argument: safe-devel" + b"private"
            self.assertEqual(po.classify_provision_failure(raw, b"", ["safe-devel"]), "unknown scan-truncated")
        self.assertEqual(po.classify_provision_failure(b"x" * 2049, b"", []), "unknown scan-truncated")
        self.assertEqual(po.classify_provision_failure(b"\xff", None, []), "unknown output-unreadable")
        self.assertEqual(po.classify_provision_failure(b"", b"No match for argument: p256",
                         ["p" + str(i) for i in range(257)]), "no-match names-omitted")
        self.assertEqual(po.classify_provision_failure(b"", b"No match for argument: safe-devel", "safe-devel"),
                         "no-match names-omitted")

    def fixture(self, fail="provision", cleanup_exit=0, timeout=False):
        calls = []
        stdout = b"unretained private stdout"
        stderr = b"No match for argument: safe-devel\nhttps://private.invalid/private?token=secret"
        def run(command, **kwargs):
            phase = {"run": "provision", "commit": "commit", "rm": "cleanup"}[command[1]]
            calls.append((phase, command, kwargs["timeout"]))
            if phase == fail and timeout:
                raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=stdout, stderr=stderr)
            exit_code = cleanup_exit if phase == "cleanup" else 1 if phase == fail else 0
            return subprocess.CompletedProcess(command, exit_code, stdout, stderr)
        runner = SubprocessRunner(timeout=600)
        runner.which = lambda tool: "/usr/bin/" + tool
        return runner, run, calls, stdout, stderr

    def invoke(self, runner, family="dnf"):
        with patch.object(hd.os, "getuid", return_value=0), patch.object(hd.uuid, "uuid4") as uuid:
            uuid.return_value.hex = "a" * 32
            return hd.provision_image(runner, family, "base@sha256:" + "b" * 64,
                                      "linux/amd64", "test-tag", ["safe-devel"])

    def test_real_failed_receipt_preserves_failure_hashes_cleanup_and_argv(self):
        for family in ("apt", "dnf", "pacman"):
            with self.subTest(family=family):
                runner, run, calls, out, err = self.fixture()
                with patch("rs9.build_native.subprocess.run", side_effect=run), self.assertRaises(ContractError) as caught:
                    self.invoke(runner, family)
                failure = caught.exception
                self.assertEqual(failure.code, "PROVISION_FAILED")
                self.assertEqual(failure.details, {"substage": "provision", "tool": family, "exit_code": 1,
                    "stdout_sha256": digest(out), "stderr_sha256": digest(err),
                    "reason_token": "no-match missing:safe-devel", "cleanup": "complete"})
                self.assertEqual([c[0] for c in calls], ["provision", "cleanup"])
                script = hd.PROVISION_COMMANDS[family].format(packages="safe-devel")
                if family == "pacman": script += " && pacman -Fy --noconfirm"
                self.assertEqual(calls[0][1], ["docker", "run", "--name", "rs9-prov-aaaaaaaaaaaa",
                    "--platform", "linux/amd64", "base@sha256:" + "b" * 64, "sh", "-c", script])
                self.assertEqual(calls[1][1], ["docker", "rm", "-f", "rs9-prov-aaaaaaaaaaaa"])
                self.assertEqual([c[2] for c in calls], [600, 30])
                self.assertEqual(runner.timeout, 600)

    def test_pacman_opt_in_propagates_with_substage_and_preserves_failure_cleanup(self):
        runner = SubprocessRunner(timeout=600)
        runner.which = lambda tool: "/usr/bin/" + tool
        calls, rows = [], []

        def run(command, **kwargs):
            calls.append((command, kwargs["timeout"]))
            if command[1] == "run":
                return subprocess.CompletedProcess(command, 1, b"", b"error: failed to prepare transaction\n")
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with patch.object(hd.os, "getuid", return_value=0), patch("rs9.build_native.subprocess.run", side_effect=run):
            with self.assertRaises(ContractError) as caught:
                hd.provision_image(
                    runner, "pacman", "base@sha256:" + "b" * 64, "linux/amd64", "test-tag", ["safe-devel"],
                    recorder=rows, substage_prefix="build-", pacman_failure_diagnostic=True,
                )
        self.assertEqual(caught.exception.code, "PROVISION_FAILED")
        self.assertEqual(caught.exception.details["reason_token"], "unknown transaction")
        self.assertEqual(caught.exception.details["substage"], "build-provision")
        self.assertEqual(caught.exception.details["cleanup"], "complete")
        self.assertEqual([call[0][1] for call in calls], ["run", "rm"])
        self.assertEqual(rows[0]["substage"], "build-provision")

    def test_pacman_full_upgrade_changes_only_sync_flag_and_preserves_default_route(self):
        runner = SubprocessRunner(timeout=600)
        runner.which = lambda tool: "/usr/bin/" + tool
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with patch.object(hd.os, "getuid", return_value=0), patch.object(hd.uuid, "uuid4") as uuid, \
                patch("rs9.build_native.subprocess.run", side_effect=run):
            uuid.return_value.hex = "a" * 32
            hd.provision_image(runner, "pacman", "fixture", "linux/amd64", "default:tag", ["python"])
            hd.provision_image(runner, "pacman", "fixture", "linux/amd64", "full:tag", ["python"],
                               pacman_full_upgrade=True)
        scripts = [command[-1] for command in calls if command[1] == "run"]
        self.assertEqual(len(scripts), 2)
        self.assertEqual(hd.PROVISION_COMMANDS["pacman"], "pacman -Sy --noconfirm --needed {packages}")
        default = hd.PROVISION_COMMANDS["pacman"].format(packages="python") + " && pacman -Fy --noconfirm"
        full = hd.PACMAN_FULL_UPGRADE_COMMAND.format(packages="python") + " && pacman -Fy --noconfirm"
        self.assertEqual(scripts, [default, full])
        self.assertEqual(full, default.replace("pacman -Sy --noconfirm --needed",
                                                "pacman -Syu --noconfirm --needed"))
        self.assertEqual([command[2] for command in calls if command[1] == "run"], ["--name", "--name"])
        self.assertEqual([command[3] for command in calls if command[1] == "run"],
                         ["rs9-prov-aaaaaaaaaaaa", "rs9-prov-aaaaaaaaaaaa"])
        self.assertEqual([command[1] for command in calls], ["run", "commit", "rm", "run", "commit", "rm"])

    def test_pacman_full_upgrade_failure_preserves_hash_cleanup_and_observer_fallback(self):
        runner = SubprocessRunner(timeout=600)
        runner.which = lambda tool: "/usr/bin/" + tool
        calls = []
        stdout, stderr = b"private stdout", b"error: conflicting files\nprivate stderr"

        def run(command, **kwargs):
            calls.append((command, kwargs["timeout"]))
            exit_code = 1 if command[1] == "run" else 0
            return subprocess.CompletedProcess(command, exit_code, stdout, stderr)

        with patch.object(hd.os, "getuid", return_value=0), patch.object(hd.uuid, "uuid4") as uuid, \
                patch.object(hd, "classify_provision_failure", side_effect=ValueError("private observer")), \
                patch("rs9.build_native.subprocess.run", side_effect=run):
            uuid.return_value.hex = "a" * 32
            with self.assertRaises(ContractError) as caught:
                hd.provision_image(runner, "pacman", "fixture", "linux/amd64", "full:tag", ["python"],
                                   pacman_full_upgrade=True)
        failure = caught.exception
        self.assertEqual(failure.code, "PROVISION_FAILED")
        self.assertEqual(failure.details, {"substage": "provision", "tool": "pacman", "exit_code": 1,
            "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr),
            "reason_token": "observation-unavailable", "cleanup": "complete"})
        self.assertEqual([command[0][1] for command in calls], ["run", "rm"])
        self.assertEqual([timeout for _, timeout in calls], [600, 30])

    def test_pacman_option_rejects_invalid_or_non_pacman_before_native_action(self):
        runner = SubprocessRunner(timeout=600)
        runner.which = lambda tool: "/usr/bin/" + tool
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            raise AssertionError("native action must not run")

        with patch("rs9.build_native.subprocess.run", side_effect=run):
            for family, value in (("pacman", 1), ("dnf", True)):
                with self.subTest(family=family, value=value), self.assertRaises(ContractError) as caught:
                    hd.provision_image(runner, family, "fixture", "linux/amd64", "test-tag", ["safe-devel"],
                                       pacman_failure_diagnostic=value)
                self.assertEqual(caught.exception.code, "INVALID_ARGUMENT")
        self.assertEqual(calls, [])

    def test_pacman_full_upgrade_rejects_invalid_or_non_pacman_before_native_action(self):
        runner = SubprocessRunner(timeout=600)
        runner.which = lambda tool: "/usr/bin/" + tool
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            raise AssertionError("native action must not run")

        with patch("rs9.build_native.subprocess.run", side_effect=run):
            for family, value in (("pacman", 1), ("dnf", True)):
                with self.subTest(family=family, value=value), self.assertRaises(ContractError) as caught:
                    hd.provision_image(runner, family, "fixture", "linux/amd64", "full:tag", ["python"],
                                       pacman_full_upgrade=value)
                self.assertEqual(caught.exception.code, "INVALID_ARGUMENT")
        self.assertEqual(calls, [])

    def test_classifier_error_cannot_replace_failure_or_cleanup(self):
        for cleanup_exit in (0, 1):
            with self.subTest(cleanup_exit=cleanup_exit):
                runner, run, calls, out, err = self.fixture(cleanup_exit=cleanup_exit)
                with patch("rs9.build_native.subprocess.run", side_effect=run), patch.object(hd,
                    "classify_provision_failure", side_effect=ValueError("private secret path")), self.assertRaises(ContractError) as caught:
                    self.invoke(runner)
                self.assertEqual(caught.exception.code, "PROVISION_FAILED")
                self.assertEqual(caught.exception.details["reason_token"], "observation-unavailable")
                self.assertEqual(caught.exception.details["cleanup"], "complete" if cleanup_exit == 0 else "failed")
                self.assertEqual(caught.exception.details["exit_code"], 1)
                self.assertEqual(caught.exception.details["stdout_sha256"], digest(out))
                self.assertNotIn("secret", repr(caught.exception.details))
                self.assertEqual([c[0] for c in calls], ["provision", "cleanup"])

    def test_success_commit_failure_and_timeout_do_not_classify(self):
        for fail, timeout in ((None, False), ("commit", False), ("provision", True)):
            with self.subTest(fail=fail, timeout=timeout):
                runner, run, calls, _, _ = self.fixture(fail=fail, timeout=timeout)
                with patch("rs9.build_native.subprocess.run", side_effect=run), patch.object(hd,
                    "classify_provision_failure", side_effect=AssertionError("must not classify")) as classifier:
                    if fail is None:
                        self.assertEqual(self.invoke(runner), "test-tag")
                    else:
                        with self.assertRaises(ContractError) as caught: self.invoke(runner)
                        self.assertEqual(caught.exception.code, "TOOL_TIMEOUT" if timeout else "PROVISION_FAILED")
                        self.assertNotIn("reason_token", caught.exception.details)
                    classifier.assert_not_called()
                self.assertEqual([c[0] for c in calls], ["provision", "cleanup"] if timeout else ["provision", "commit", "cleanup"])
