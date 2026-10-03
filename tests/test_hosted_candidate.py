"""Diagnostic receipts cannot pass incomplete candidate qualification."""
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from rs9.adopt_candidate import validate_receipts
from rs9.errors import ContractError
from rs9.hosted_candidate import (
    REQUIRED_RECEIPTS,
    REQUIRED_RECEIPT_FILES,
    command_probes,
    prerequisite_failures,
    run_lane,
    summarize,
    wheel_diagnostics,
)
from rs9.scratch import canonical


def _populate_receipts(receipts_dir: Path, commit: str):
    for lane, system in REQUIRED_RECEIPTS:
        fname = f"{lane}-{system}.json"
        doc = {
            "schema": "rs9.hosted-candidate-diagnostic.v1alpha1",
            "source_commit": commit,
            "trust_root": "hosted-candidate-unattested",
            "lane": lane,
            "system": system,
            "status": "blocked",
            "production_enabled": False,
            "publication_authority": False,
            "mandatory_gates_satisfied": False,
            "artifacts": [],
            "blockers": ["test-blocker"],
        }
        (receipts_dir / fname).write_bytes(canonical(doc))


class HostedCandidateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.scratch = self.root / "scratch"
        self.receipts = self.root / "receipts"
        self.scratch.mkdir()
        self.receipts.mkdir()
        self.repo = Path(__file__).resolve().parents[1]
        self.environment = patch.dict("os.environ", {"GITHUB_SHA": "1" * 40})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_failed_authentication_receipt_has_no_artifacts_or_pass(self):
        with patch("rs9.hosted_candidate.capture_generation", side_effect=ContractError("FETCH_FAILED", "Unavailable")):
            status = run_lane(self.repo, self.scratch, self.receipts, "authenticate", "generation")
        self.assertEqual(status, 2)
        value = json.loads((self.receipts / "authenticate-generation.json").read_bytes())
        self.assertEqual(value["artifacts"], [])
        self.assertFalse(value["mandatory_gates_satisfied"])
        self.assertFalse(value["production_enabled"])
        self.assertEqual(value["blockers"], ["FETCH_FAILED"])

    def test_native_prerequisites_and_summary_cannot_succeed(self):
        self.assertEqual(run_lane(self.repo, self.scratch, self.receipts, "deb", "amd64"), 2)
        # Summarize with only 1 receipt must fail because 12 receipts are missing
        with self.assertRaises(ContractError) as ctx:
            summarize(self.repo, self.receipts)
        self.assertEqual(ctx.exception.code, "HOSTED_RECEIPTS")

        # Now populate all 13 required receipts
        _populate_receipts(self.receipts, "1" * 40)
        self.assertEqual(summarize(self.repo, self.receipts), 2)

        workflow_hash = hashlib.sha256((self.repo / ".github/workflows/rs9-candidate-tests.yml").read_bytes()).hexdigest()
        manifest = validate_receipts(self.receipts, "1" * 40, workflow_hash)
        self.assertEqual(manifest["status"], "incomplete-candidate")
        self.assertEqual(len(manifest["files"]), 13)

        # Tampering with a receipt invalidates validation
        (self.receipts / "deb-amd64.json").write_bytes(b"{}")
        with self.assertRaises(ContractError):
            validate_receipts(self.receipts, "1" * 40, workflow_hash)

    def test_workflow_is_read_only_pinned_and_push_triggered(self):
        text = (self.repo / ".github/workflows/rs9-candidate-tests.yml").read_text()
        self.assertIn("  push:\n    branches: [main]", text)
        self.assertIn("contents: read", text)
        for forbidden in ("secrets.", "id-token:", "environment:", "pull_request_target:", "deploy-pages", "contents: write", "pages: write"):
            self.assertNotIn(forbidden, text)
        uses = re.findall(r"uses:\s*(\S+)", text)
        self.assertTrue(uses)
        self.assertTrue(all(re.fullmatch(r"[\w-]+/[\w-]+@[0-9a-f]{40}", action) for action in uses))
        self.assertEqual(text.count("persist-credentials: false"), text.count("uses: actions/checkout@"))

    def test_matrix_label_cannot_assert_another_host_architecture(self):
        with patch("rs9.hosted_candidate.platform.system", return_value="Linux"), patch("rs9.hosted_candidate.platform.machine", return_value="x86_64"):
            self.assertEqual(run_lane(self.repo, self.scratch, self.receipts, "wheels", "aarch64-linux"), 2)
        value = json.loads((self.receipts / "wheels-aarch64-linux.json").read_bytes())
        self.assertEqual(value["blockers"], ["CANDIDATE_PLATFORM"])
        self.assertEqual(value["artifacts"], [])

    def test_prerequisite_failures_derived_from_targets(self):
        deb_blockers = prerequisite_failures(self.repo, "deb", system="amd64")
        self.assertIn("maintainer-unassigned", deb_blockers)
        self.assertIn("authenticated-container-digest-unavailable", deb_blockers)
        self.assertIn("complete-dependency-derivation-unqualified", deb_blockers)

        pacman_blockers = prerequisite_failures(self.repo, "pacman", system="x86_64-linux")
        self.assertIn("authenticated-container-digest-unavailable", pacman_blockers)
        self.assertIn("arch-snapshot-unavailable", pacman_blockers)
        self.assertIn("maintainer-unassigned", pacman_blockers)

        nix_blockers = prerequisite_failures(self.repo, "nix", system="x86_64-linux")
        self.assertIn("nixpkgs-lock-unavailable", nix_blockers)
        self.assertIn("native-closure-and-scenario-A-unqualified", nix_blockers)

        # Test with resolved maintainer and container digest in mocked targets
        custom_targets = {
            "schema": "rs9.live1-candidate-targets.v1alpha1",
            "production_enabled": False,
            "maintainer": "test-maintainer@example.org",
            "pacman": {"architectures": ["x86_64"], "container_digest": "sha256:abc", "snapshot": "2026-10-01"},
            "rpm": {"distribution": "fedora-43", "architectures": ["x86_64"], "container_digests": {"x86_64": "sha256:def"}},
            "deb": {"distribution": "ubuntu-26.04", "suite": "resolute", "architectures": ["amd64"], "container_digests": {"amd64": "sha256:123"}},
            "nix": {"nixpkgs_revision": "rev1", "nixpkgs_nar_hash": "nar1", "outputs_exposed": True},
            "pin_status": "pinned",
        }
        mock_repo = self.root / "mock_repo"
        (mock_repo / "operators/live1").mkdir(parents=True)
        (mock_repo / "operators/live1/targets.json").write_bytes(canonical(custom_targets))

        deb_resolved = prerequisite_failures(mock_repo, "deb", system="amd64")
        self.assertNotIn("maintainer-unassigned", deb_resolved)
        self.assertNotIn("authenticated-container-digest-unavailable", deb_resolved)
        self.assertIn("complete-dependency-derivation-unqualified", deb_resolved)

        pacman_resolved = prerequisite_failures(mock_repo, "pacman", system="x86_64-linux")
        self.assertNotIn("maintainer-unassigned", pacman_resolved)
        self.assertNotIn("authenticated-container-digest-unavailable", pacman_resolved)
        self.assertNotIn("arch-snapshot-unavailable", pacman_resolved)

        nix_resolved = prerequisite_failures(mock_repo, "nix", system="x86_64-linux")
        self.assertNotIn("nixpkgs-lock-unavailable", nix_resolved)
        self.assertNotIn("native-closure-and-scenario-A-unqualified", nix_resolved)
        self.assertIn("nix-build-check-run-harness-unimplemented", nix_resolved)

    def test_command_probes_tfsl_batch_truthful_empty_input(self):
        # tfsl-batch must only use truthful empty input probe, never --help or --version
        probes_batch = command_probes("tfsl-batch")
        self.assertEqual(probes_batch, [[]])
        self.assertNotIn(["--help"], probes_batch)
        self.assertNotIn(["--version"], probes_batch)

        # other commands use version and help
        self.assertEqual(command_probes("tfsl"), [["--version"], ["--help"]])
        self.assertEqual(command_probes("tfsb"), [["--version"], ["--help"]])
        self.assertEqual(command_probes("tfsb-studio-service"), [])
        self.assertEqual(command_probes("unknown-command"), [])
        self.assertEqual(command_probes("tfss"), [["--version"], ["--help"]])

    def test_darwin_offline_status_unsupported_not_run(self):
        with patch("rs9.hosted_candidate.platform.system", return_value="Darwin"), \
             patch("rs9.hosted_candidate.platform.machine", return_value="arm64"):
            mock_capture = MagicMock()
            mock_capture.source = {"package.json": json.dumps({"name": "theme-forge-stellar-loom"})}
            mock_capture.record = {"payloads": [{}]}
            mock_intent = {"project": {"id": "theme-forge-stellar-loom"}}
            mock_profile = {"status": "consistent"}
            mock_captures = [(mock_capture, mock_intent, mock_profile)]

            mock_build = MagicMock()
            mock_build.filename = "theme_forge_stellar_loom-0.4.0-py3-none-any.whl"
            mock_build.sha256 = "0" * 64
            mock_build.record = {"release_record_sha256": "1" * 64}

            with patch("rs9.hosted_candidate.capture_generation", return_value=mock_captures), \
                 patch("rs9.hosted_candidate.shutil.which", return_value="/usr/bin/node"), \
                 patch("rs9.hosted_candidate.subprocess.run", return_value=MagicMock(stdout="v22.0.0\n")), \
                 patch("rs9.hosted_candidate.verify_double_build", return_value=(mock_build, mock_build)), \
                 patch("rs9.hosted_candidate.verify_offline_venv_lifecycle") as mock_lifecycle:
                results = wheel_diagnostics(self.repo, self.scratch, None, "hosted:test")

            mock_lifecycle.assert_not_called()
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["status"], "not-run")
            self.assertEqual(results[0]["reason"], "darwin-offline-isolation-unsupported")
            self.assertEqual(results[0]["network_isolation"], "unsupported")
            self.assertEqual(results[0]["lifecycle"], [])

            with patch("rs9.hosted_candidate.wheel_diagnostics", return_value=results):
                status = run_lane(self.repo, self.scratch, self.receipts, "wheels", "aarch64-darwin")
            self.assertEqual(status, 2)
            receipt_data = json.loads((self.receipts / "wheels-aarch64-darwin.json").read_bytes())
            self.assertIn("darwin-offline-isolation-unsupported", receipt_data["blockers"])
            self.assertIn("native-platform-verifier-unimplemented", receipt_data["blockers"])

    def test_linux_netns_drops_root_to_runner(self):
        with patch("rs9.hosted_candidate.platform.system", return_value="Linux"), \
             patch("rs9.hosted_candidate.platform.machine", return_value="x86_64"), \
             patch("rs9.hosted_candidate.os.getuid", return_value=1001), \
             patch("rs9.hosted_candidate.os.getgid", return_value=1001):

            mock_capture = MagicMock()
            mock_capture.source = {"package.json": json.dumps({"name": "theme-forge-stellar-loom"})}
            mock_capture.record = {"payloads": [{}]}
            mock_intent = {"project": {"id": "theme-forge-stellar-loom"}}
            mock_profile = {"status": "consistent"}
            mock_captures = [(mock_capture, mock_intent, mock_profile)]
            mock_build = MagicMock()
            mock_build.filename = "theme_forge_stellar_loom-0.4.0-py3-none-any.whl"
            mock_build.sha256 = "0" * 64
            mock_build.record = {"release_record_sha256": "1" * 64}

            def fake_which(cmd):
                if cmd == "node": return "/usr/bin/node"
                return None

            with patch("rs9.hosted_candidate.capture_generation", return_value=mock_captures), \
                 patch("rs9.hosted_candidate.shutil.which", side_effect=fake_which), \
                 patch("rs9.hosted_candidate.subprocess.run", return_value=MagicMock(stdout="v22.0.0\n")), \
                 patch("rs9.hosted_candidate.verify_double_build", return_value=(mock_build, mock_build)):
                with self.assertRaises(ContractError) as ctx:
                    wheel_diagnostics(self.repo, self.scratch, None, "hosted:test")
                self.assertEqual(ctx.exception.code, "NETWORK_ISOLATION_UNAVAILABLE")

    def test_wheel_diagnostics_collects_failures_without_aborting_lane(self):
        with patch("rs9.hosted_candidate.platform.system", return_value="Linux"), \
             patch("rs9.hosted_candidate.platform.machine", return_value="x86_64"), \
             patch("rs9.hosted_candidate.os.getuid", return_value=1001), \
             patch("rs9.hosted_candidate.os.getgid", return_value=1001):

            mock_cap1 = MagicMock()
            mock_cap1.source = {"package.json": json.dumps({"name": "theme-forge-stellar-loom"})}
            mock_cap1.record = {"payloads": [{}]}
            mock_intent1 = {"project": {"id": "theme-forge-stellar-loom"}}

            mock_cap2 = MagicMock()
            mock_cap2.source = {"package.json": json.dumps({"name": "theme-forge-solar-sail"})}
            mock_cap2.record = {"payloads": [{}]}
            mock_intent2 = {"project": {"id": "theme-forge-solar-sail"}}

            mock_profile = {"status": "consistent"}
            mock_captures = [(mock_cap1, mock_intent1, mock_profile), (mock_cap2, mock_intent2, mock_profile)]

            mock_build = MagicMock()
            mock_build.filename = "test.whl"
            mock_build.sha256 = "0" * 64
            mock_build.wheel_path = "/path/test.whl"
            mock_build.record = {"release_record_sha256": "1" * 64}

            def fake_which(cmd):
                return f"/usr/bin/{cmd}"

            # Make first product fail double build, second product succeed
            build_calls = [0]
            def fake_double_build(*args, **kwargs):
                build_calls[0] += 1
                if build_calls[0] == 1:
                    raise ContractError("DOUBLE_BUILD_MISMATCH", "Non-deterministic")
                return (mock_build, mock_build)

            with patch("rs9.hosted_candidate.capture_generation", return_value=mock_captures), \
                 patch("rs9.hosted_candidate.shutil.which", side_effect=fake_which), \
                 patch("rs9.hosted_candidate.subprocess.run", return_value=MagicMock(stdout="v22.0.0\n", returncode=0)) as run, \
                 patch("rs9.hosted_candidate.verify_double_build", side_effect=fake_double_build), \
                 patch("rs9.hosted_candidate.stage_payload"), \
                 patch("rs9.hosted_candidate.verify_offline_venv_lifecycle", return_value={"clean_uninstall_verified": True}):
                results = wheel_diagnostics(self.repo, self.scratch, None, "hosted:test")

            # Both products were processed; lane was not aborted on product 1's failure
            self.assertEqual(len(results), 2)
            self.assertEqual(results[0]["project"], "theme-forge-stellar-loom")
            self.assertEqual(results[0]["status"], "diagnostic-fail")
            self.assertEqual(results[0]["error"], "DOUBLE_BUILD_MISMATCH")

            self.assertEqual(results[1]["project"], "theme-forge-solar-sail")
            self.assertEqual(results[1]["status"], "diagnostic-pass")
            executed = [call.args[0] for call in run.call_args_list if "--net" in call.args[0]]
            self.assertTrue(executed)
            for command in executed:
                self.assertIn("/usr/bin/setpriv", command)
                self.assertIn("--reuid=1001", command)
                self.assertIn("--regid=1001", command)
                self.assertIn("--clear-groups", command)
            self.assertNotIn("detail", results[0])


if __name__ == "__main__":
    unittest.main()
