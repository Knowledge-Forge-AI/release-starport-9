"""Original Nix failure custody and the CONT20 staged-source regression."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from rs9.errors import ContractError
from rs9.hosted_nix import command, prepare_input
from rs9.nix_build_diagnostic import (MAX_STDERR, PIN_FILE, classify_stderr,
                                    experiment_source_identity, retain_failure, stage_experiment_pin)
from rs9.nix_proot_dbus_pin import DBUS_SESSION_CONFIG_SHA256
from rs9.release_core import digest

ROOT = Path(__file__).resolve().parents[1]
PIN = ('DBUS_SESSION_CONFIG_SHA256 = "' + DBUS_SESSION_CONFIG_SHA256 + '"\n').encode()
MISSING = ("error: path '/nix/store/" + "0" * 32 + "-source/" + PIN_FILE + "' does not exist\n").encode()
BUILDER = ("error: builder for '/nix/store/" + "0" * 32 +
           "-rs9-nebular-proot-guest-root.drv' failed with exit code 1\n").encode()


class StagingTests(unittest.TestCase):
    def test_real_preparation_exposes_missing_pin_then_exact_allowlisted_repair(self):
        # Capture validation is later than the real source-copy boundary.
        # This is a source reproduction, never an authentic released build.
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp).resolve()
            with self.assertRaises(ContractError) as caught:
                prepare_input({"repository": ROOT, "scratch": scratch, "captures": []})
            self.assertEqual(caught.exception.code, "NIX_CAPTURE")
            source = scratch / "nix-source"
            self.assertFalse((source / PIN_FILE).exists())
            expression = source / "nix/nebular-proot-experiment.nix"
            before = expression.read_bytes()
            self.assertIn(b"builtins.readFile ../src/rs9/nix_proot_dbus_pin.py", before)
            staged = stage_experiment_pin(ROOT, source)
            self.assertEqual((source / PIN_FILE).read_bytes(), PIN)
            self.assertEqual(staged, {"path": PIN_FILE, "sha256": digest(PIN), "size": len(PIN)})
            self.assertEqual(expression.read_bytes(), before)
            identity = experiment_source_identity(ROOT, source)
            self.assertEqual(identity["nix/nebular-proot-experiment.nix"], digest(before))
            expression.write_bytes(before + b"# mismatch\n")
            with self.assertRaises(ContractError) as changed:
                experiment_source_identity(ROOT, source)
            self.assertEqual(changed.exception.code, "NIX_PIN")
            expression.write_bytes(before)
            self.assertEqual(list((source / "src").rglob("*.py")), [source / PIN_FILE])
            # Every upward reference in the staged Nix source now resolves.
            for file in (source / "nix").glob("*.nix"):
                for relative in re.findall(r"(?<![\w/])\.\./[\w/.-]+", file.read_text()):
                    self.assertTrue((file.parent / relative).is_file(), relative)

    def test_invalid_source_pins_and_aliases_fail_before_producer(self):
        malformed = [PIN.replace(b"\n", b"\r\n"), PIN.rstrip(), PIN.upper(),
                     PIN + b"# comment\n", PIN.replace(DBUS_SESSION_CONFIG_SHA256.encode(), b"0" * 64),
                     b"x" * 257, b"", b'"docstring"\n' + PIN]
        for data in malformed:
            with self.subTest(data_len=len(data)), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                path = root / PIN_FILE
                path.parent.mkdir(parents=True)
                path.write_bytes(data)
                with self.assertRaises(ContractError) as caught:
                    stage_experiment_pin(root, root / "source")
                self.assertEqual(caught.exception.code, "NIX_PIN")
                self.assertFalse((root / "source").exists())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / PIN_FILE
            path.parent.mkdir(parents=True)
            physical = root / "physical"
            physical.write_bytes(PIN)
            path.symlink_to(physical)
            with self.assertRaises(ContractError):
                stage_experiment_pin(root, root / "source")

    def test_missing_source_and_destination_alias_or_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with self.assertRaises(ContractError):
                stage_experiment_pin(root, root / "source")
            source = root / "source"
            source.mkdir()
            (source / "src").symlink_to(ROOT / "src", target_is_directory=True)
            with self.assertRaises(ContractError):
                stage_experiment_pin(ROOT, source)
            (source / "src").unlink()
            path = source / PIN_FILE
            path.parent.mkdir(parents=True)
            path.write_bytes(b"different")
            with self.assertRaises(ContractError):
                stage_experiment_pin(ROOT, source)
            self.assertEqual(path.read_bytes(), b"different")


class ClassificationTests(unittest.TestCase):
    def test_pinned_nix_2_31_2_error_formats(self):
        # Source-derived message controls, not captured native producer output.
        # NixOS/nix 2.31.2: libutil/file-system.cc readFile;
        # libstore/unix/build/derivation-builder.cc unprepareBuild;
        # libutil/unix/processes.cc statusToString.
        missing = MISSING.replace(b"path ", b"opening file ").replace(
            b" does not exist", b": No such file or directory")
        builder = ("error: Cannot build '/nix/store/" + "0" * 32 +
                   "-rs9-nebular-proot-guest-root.drv'.\n"
                   "       Reason: builder failed with exit code 1.\n").encode()
        self.assertEqual(classify_stderr(missing)["cause_token"], "eval-path-missing")
        self.assertEqual(classify_stderr(missing)["missing_path"], PIN_FILE)
        self.assertEqual(classify_stderr(builder)["cause_token"], "builder-failed")
        self.assertEqual(classify_stderr(builder)["failed_drv_name"], "rs9-nebular-proot-guest-root")
        self.assertEqual(classify_stderr(missing + builder)["cause_token"], "conflicting")
        dependency = builder.replace(b"builder failed with exit code 1", b"1 dependency failed")
        self.assertEqual(classify_stderr(dependency)["cause_token"], "unknown")
        for raw in (missing, builder):
            self.assertEqual(classify_stderr(raw, complete=False)["cause_token"], "stream-incomplete")
            self.assertEqual(classify_stderr(raw + b"\x1b[31m")["cause_token"], "stream-invalid")
            self.assertEqual(classify_stderr(raw + b"password=withheld")["cause_token"], "stream-withheld")

    def test_causal_patterns_are_closed_and_do_not_include_prose(self):
        cases = [(MISSING, "eval-path-missing", "evaluation"),
                 (MISSING.replace(b"path ", b"getting status of ").replace(
                     b" does not exist", b": No such file or directory"), "eval-path-missing", "evaluation"),
                 (b"error: assertion 'some condition' failed\n", "eval-assertion-failed", "evaluation"),
                 (b"error: attribute 'someAttribute' missing\n", "eval-attribute-missing", "evaluation"),
                 (BUILDER + b"sha256sum: WARNING: 1 computed checksum did NOT match\n", "builder-failed", "build"),
                 (b"error: hash mismatch in fixed-output derivation\n", "fixed-output-hash-mismatch", "build"),
                 (b"error: unable to download 'https://example.invalid/path'\n", "fetch-failed", "fetch"),
                 (b"error: creating sandbox: Operation not permitted\n", "permission-or-sandbox", "unknown"),
                 (b"error: something else\n", "unknown", "unknown")]
        for raw, cause, phase in cases:
            with self.subTest(cause=cause):
                record = classify_stderr(raw)
                self.assertEqual((record["cause_token"], record["phase"]), (cause, phase))
                self.assertEqual(record["sha256"], digest(raw))
                self.assertEqual(record["raw_bytes"], len(raw))
                self.assertNotIn("example.invalid", json.dumps(record))
        self.assertEqual(classify_stderr(MISSING)["missing_path"], PIN_FILE)
        self.assertEqual(classify_stderr(BUILDER)["failed_drv_name"], "rs9-nebular-proot-guest-root")
        self.assertNotIn("failed_drv_name", classify_stderr(BUILDER.replace(b"rs9-nebular", b"private-name")))
        self.assertNotIn("missing_path", classify_stderr(MISSING.replace(b"-source/", b"-private/")))
        self.assertEqual(classify_stderr(MISSING + BUILDER)["cause_token"], "conflicting")

    def test_absent_malformed_and_truncated_streams_withhold_cause(self):
        for raw, complete, token in [(None, True, "stream-absent"), (b"", True, "stream-empty"),
                (b"\xff" + MISSING, True, "stream-invalid"), (MISSING + b"\x00", True, "stream-invalid"),
                (MISSING + b"\x1b", True, "stream-invalid"), (MISSING, False, "stream-incomplete"),
                (MISSING + b"x" * MAX_STDERR, True, "stream-incomplete")]:
            with self.subTest(token=token):
                result = classify_stderr(raw, complete=complete)
                self.assertEqual(result["cause_token"], token)
                self.assertNotIn("missing_path", result)
                self.assertEqual(result["sha256"], digest(raw or b""))

    def test_secret_bearing_streams_are_digest_only(self):
        secrets = [b"password=example-value", ("ghp_" + "a" * 36).encode(),
                   ("-----" + "BEGIN PRIVATE KEY-----").encode(), b"Cookie: session-value"]
        for secret in secrets:
            with self.subTest(kind=secret[:4]):
                result = classify_stderr(MISSING + secret)
                self.assertEqual(result["cause_token"], "stream-withheld")
                self.assertNotIn("missing_path", result)
                self.assertNotIn(secret.decode(), json.dumps(result))


class ProducerTests(unittest.TestCase):
    def test_execute_keeps_first_build_failure_before_runtime_without_replay(self):
        from tests.test_hosted_nix_proot import HostedNixProotExecuteTests
        from rs9.hosted_nix_proot import execute
        control = HostedNixProotExecuteTests()
        control.setUp()
        self.addCleanup(control.doCleanups)
        metadata = json.dumps({"locks": {"nodes": {"nixpkgs": {"locked": control.locked}}}}).encode()
        outcomes = [subprocess.CompletedProcess([], 0, metadata, b""),
                    subprocess.CompletedProcess([], 1, b"", MISSING)]
        with patch.dict("os.environ", {"RUNNER_TEMP": str(control.scratch / "runner")}), \
                patch("rs9.hosted_nix_proot.prepare_input", return_value=(control.work, control.work, {})), \
                patch("rs9.hosted_nix.subprocess.run", side_effect=outcomes) as producer, \
                patch("rs9.hosted_nix_proot.evaluate_proot_experiment") as runtime:
            with self.assertRaises(ContractError) as caught:
                execute(control.context)
        self.assertEqual(caught.exception.code, "NIX_EXECUTION")
        self.assertEqual(producer.call_count, 2)
        self.assertEqual(producer.call_args_list[0].args[0][1:3], ["flake", "metadata"])
        self.assertEqual(producer.call_args_list[1].args[0][1], "build")
        runtime.assert_not_called()
        record = json.loads((control.work / "diagnostics/nix-build-failure.json").read_bytes())
        self.assertEqual(record["stderr"]["sha256"], digest(MISSING))
        self.assertEqual(record["source"]["pin_file"]["sha256"], digest(PIN))
        self.assertEqual(record["source"]["staged_source"]["flake.nix"], digest((ROOT / "flake.nix").read_bytes()))

    def run_failure(self, root, *, timeout=False, writer=None):
        def observe(stderr, details, *, complete):
            return (writer or retain_failure)(root, {"system": "x86_64-linux"}, stderr, details, complete=complete)
        result = subprocess.CompletedProcess(["nix", "build"], 1, b"", MISSING)
        outcome = subprocess.TimeoutExpired(["nix", "build"], 1, output=b"", stderr=MISSING) if timeout else result
        with patch("rs9.hosted_nix.subprocess.run", side_effect=[outcome]) as producer:
            with self.assertRaises(ContractError) as caught:
                command(["nix", "build"], on_failure=observe)
        producer.assert_called_once_with(["nix", "build"], cwd=None, env=None, capture_output=True, timeout=3600)
        return caught.exception

    def test_original_failure_is_retained_with_exact_contract_and_exclusive_mode(self):
        for mode in (0o022, 0o077):
            with self.subTest(umask=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                previous = os.umask(mode)
                try:
                    error = self.run_failure(root)
                finally:
                    os.umask(previous)
                path = root / "nix-build-failure.json"
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                record = json.loads(path.read_bytes())
                self.assertEqual(error.code, "NIX_EXECUTION")
                self.assertEqual(error.details["substage"], "nix-build")
                self.assertEqual(error.details["exit_code"], 1)
                self.assertEqual(error.details["stdout_sha256"], digest(b""))
                self.assertEqual(error.details["stderr_sha256"], digest(MISSING))
                self.assertEqual(error.details["diagnostic_sha256"], digest(path.read_bytes()))
                self.assertEqual(record["origin"], "original-producer-attempt")
                self.assertIs(record["diagnostic_replay"], False)
                self.assertIs(record["application_qualified"], False)
                self.assertEqual(record["producer"]["code"], "NIX_EXECUTION")
                self.assertNotIn(str(root), path.read_text())
                original = path.read_bytes()
                second = self.run_failure(root)
                self.assertEqual(second.code, "NIX_EXECUTION")
                self.assertEqual(second.details["diagnostic_token"], "diagnostic-unavailable")
                self.assertEqual(path.read_bytes(), original)

    def test_timeout_is_incomplete_and_writer_failure_cannot_mask_failure(self):
        for timeout in (True, False):
            with self.subTest(timeout=timeout), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                error = self.run_failure(root, timeout=timeout)
                record = json.loads((root / "nix-build-failure.json").read_bytes())
                if timeout:
                    self.assertEqual(error.code, "TOOL_TIMEOUT")
                    self.assertNotIn("exit_code", error.details)
                    self.assertIs(record["stderr"]["complete"], False)
                broken = self.run_failure(root, timeout=timeout, writer=Mock(side_effect=RuntimeError("writer")))
                self.assertEqual((broken.code, broken.details["substage"], broken.details["stderr_sha256"]),
                                 (error.code, "nix-build", digest(MISSING)))
                self.assertEqual(broken.details["diagnostic_token"], "diagnostic-unavailable")

    def test_callback_cannot_replace_producer_fields(self):
        fake = Mock(return_value={"exit_code": 0, "substage": "different", "stderr_sha256": "0" * 64})
        with patch("rs9.hosted_nix.subprocess.run", return_value=subprocess.CompletedProcess([], 1, b"", MISSING)):
            with self.assertRaises(ContractError) as caught:
                command(["nix", "build"], on_failure=fake)
        self.assertEqual(caught.exception.details, {"tool": "nix", "substage": "nix-build", "exit_code": 1,
                         "stdout_sha256": digest(b""), "stderr_sha256": digest(MISSING)})

    def test_success_and_production_contract_unchanged(self):
        observer = Mock()
        with patch("rs9.hosted_nix.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"output", MISSING)):
            self.assertEqual(command(["nix", "build"], on_failure=observer), b"output")
        observer.assert_not_called()
        with patch("rs9.hosted_nix.subprocess.run", return_value=subprocess.CompletedProcess([], 1, b"", MISSING)):
            with self.assertRaises(ContractError) as caught:
                command(["nix", "build"])
        self.assertEqual(caught.exception.details, {"tool": "nix", "substage": "nix-build", "exit_code": 1,
                         "stdout_sha256": digest(b""), "stderr_sha256": digest(MISSING)})

    def test_success_cannot_be_retained_and_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with self.assertRaises(ValueError):
                retain_failure(root, {}, b"", {"exit_code": 0}, complete=True)
            target = root / "target"
            target.write_bytes(b"preserved")
            (root / "nix-build-failure.json").symlink_to(target)
            self.assertEqual(self.run_failure(root).code, "NIX_EXECUTION")
            self.assertEqual(target.read_bytes(), b"preserved")

    def test_pipeline_remains_all_fail_even_when_a_diagnostic_is_present(self):
        from tests.test_hosted_nix_proot import PipelineReceiptTests
        with tempfile.TemporaryDirectory() as tmp:
            error = self.run_failure(Path(tmp).resolve())
        code, record = PipelineReceiptTests().run_lane(None, error=error)
        self.assertEqual(code, 2)
        self.assertTrue(all(g["status"] == "fail" for g in record["gates"]))
        self.assertEqual(record["execution_error"], "NIX_EXECUTION")
        self.assertEqual(record["execution_error_detail"]["diagnostic_token"], "eval-path-missing")
        self.assertIs(record["application_qualified"], False)
        self.assertIs(record["qualification_authority"], False)


if __name__ == "__main__":
    unittest.main()
