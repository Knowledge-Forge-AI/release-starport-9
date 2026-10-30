"""Controlled child results for explicit setup and offline installed reuse."""
import hashlib
import json
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9 import nebular070_universal_consumer as consumer
from rs9.errors import ContractError


class UniversalSetupConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name).resolve()
        self.body = b"synthetic native archive"
        self.asset = {"size": len(self.body), "sha256": hashlib.sha256(self.body).hexdigest()}
        self.spec = {"asset": self.asset, "manifest_sha256": "a" * 64}
        self.env = {"HOME": str(self.work / "home"), "XDG_CACHE_HOME": str(self.work / "home/.cache")}
        self.cache = self.work / "home/.cache/rs9/theme-forge-nebular-fusion"
        self.archive = self.cache / "archives" / (self.asset["sha256"] + ".tgz")
        self.calls = []

    def result(self, code=0, stdout="", stderr=""):
        return dict(exit_code=code, signal=None, stdout_token=stdout, stderr_token=stderr,
                    stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
                    stderr_sha256=hashlib.sha256(stderr.encode()).hexdigest(),
                    cleanup_known=True, output_complete=True, forced_cleanup=False,
                    timed_out=False, output_limit_exceeded=False, duration_ms=1)

    def fake_run(self, argv, env, work, prefix, timeout, *, runner):
        self.calls.append((list(argv), tuple(prefix)))
        if argv == [self.work / "tfnf"]:
            return self.result(1, stderr="TFNF_RUNTIME_MISSING: Run tfnf install-runtime before launching.")
        downloaded = not self.archive.exists()
        if downloaded:
            self.archive.parent.mkdir(parents=True)
            self.archive.write_bytes(self.body)
        value = {"schema": "theme-forge-nebular-fusion.runtime-install.v1", "version": "0.7.0",
                 "target": "linux-x64-gnu", "archive_sha256": self.asset["sha256"],
                 "archive_bytes": self.asset["size"], "manifest_sha256": "a" * 64,
                 "downloaded": downloaded,
                 "redirect_hosts": ["release-assets.githubusercontent.com"] if downloaded else []}
        return self.result(stdout=json.dumps(value))

    def setup_runtime(self):
        return consumer.install_runtime_for_consumer(
            spec=self.spec, target="linux-x64-gnu", command=self.work / "tfnf",
            python=self.work / "python", env=self.env, work=self.work,
            prefix=("network-denial",), runner=object())

    def test_only_explicit_setup_has_network_and_offline_reuse_verifies_same_bytes(self):
        with patch("rs9.tf_pypi_consumer._nebular_run", side_effect=self.fake_run):
            value = self.setup_runtime()
        self.assertEqual([prefix for _argv, prefix in self.calls],
                         [("network-denial",), (), ("network-denial",)])
        self.assertEqual(value["archive_sha256"], self.asset["sha256"])
        self.assertFalse(value["publication_admitted"])
        self.assertNotIn(str(self.work), json.dumps(value))

    def test_setup_process_failures_do_not_create_success_receipts(self):
        for change in ({"exit_code": 1}, {"forced_cleanup": True},
                       {"cleanup_known": False}, {"output_complete": False}):
            self.calls.clear()
            def fake(*args, **kwargs):
                value = self.fake_run(*args, **kwargs)
                return {**value, **change} if len(self.calls) == 2 else value
            with self.subTest(fields=tuple(change)), patch(
                    "rs9.tf_pypi_consumer._nebular_run", side_effect=fake), self.assertRaises(ContractError):
                self.setup_runtime()
            self.assertEqual(len(self.calls), 2)
            shutil.rmtree(self.cache, ignore_errors=True)
    def test_changed_archive_or_private_extra_setup_field_is_refused(self):
        for kind in ("archive", "receipt"):
            self.calls.clear()
            def fake(*args, **kwargs):
                value = self.fake_run(*args, **kwargs)
                if len(self.calls) == 2:
                    if kind == "archive":
                        self.archive.write_bytes(b"tampered")
                    else:
                        receipt = json.loads(value["stdout_token"])
                        receipt["signed_url"] = "https://private.invalid/?token=PRIVATE"
                        value["stdout_token"] = json.dumps(receipt)
                return value
            with self.subTest(kind=kind), patch(
                    "rs9.tf_pypi_consumer._nebular_run", side_effect=fake), self.assertRaises(ContractError):
                self.setup_runtime()
            self.assertEqual(len(self.calls), 2)
            shutil.rmtree(self.cache, ignore_errors=True)


class UniversalHostedContextTests(unittest.TestCase):
    def call(self):
        return consumer.consume_universal_wheel(
            Path("absent.whl"), b"", b"", {}, Path("absent-work"),
            target="linux-x64-gnu", source={"commit": "a" * 40, "tree": "b" * 40},
            run_id="17", run_attempt="1", repository=Path("."))

    def environment(self):
        return {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "Knowledge-Forge-AI/release-starport-9",
                "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ID": "17",
                "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a" * 40}

    def test_local_branch_foreign_repository_and_rerun_are_not_qualifying_contexts(self):
        for change in ({"GITHUB_ACTIONS": "false"}, {"GITHUB_REF": "refs/heads/staging"},
                       {"GITHUB_REPOSITORY": "unrelated/repository"},
                       {"GITHUB_RUN_ATTEMPT": "2"}, {"GITHUB_SHA": "c" * 40}):
            with self.subTest(fields=tuple(change)), patch.dict(
                    "os.environ", {**self.environment(), **change}, clear=True), patch.object(
                    consumer, "inspect_universal_wheel") as inspect, self.assertRaisesRegex(
                    ContractError, "HOSTED_CONTEXT"):
                self.call()
            inspect.assert_not_called()

    def test_source_tree_mismatch_refuses_before_wheel_or_native_work(self):
        with patch.dict("os.environ", self.environment(), clear=True), patch(
                "rs9.tf_pypi_nebular070_publish._git_output", side_effect=["a" * 40, "c" * 40]), \
             patch.object(consumer, "inspect_universal_wheel") as inspect, \
             self.assertRaisesRegex(ContractError, "SOURCE"):
            self.call()
        inspect.assert_not_called()
