"""Run-12 handoff retains exact adoption, collection, and diagnostic boundaries."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

# Ensure both src and tests directories are discoverable for sub-fixtures
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(ROOT / "tests"))

from tests import test_run_hosted9 as previous

SCRIPT = ROOT / "operators/live1/run-hosted12.py"
spec = importlib.util.spec_from_file_location("rs9_run_hosted12", SCRIPT)
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)


class Run12Tests(unittest.TestCase):
    def check_previous_boundary(self, method):
        with patch.object(previous, "operator", operator):
            getattr(previous.Run9Tests, method)(self)

    def test_exact_external_acceptance_and_false_readiness(self):
        """Exact authority forwarding: manager attestation is forwarded without readiness flag edit."""
        self.check_previous_boundary("test_external_acceptance_is_forwarded_once_without_readiness_flag_edit")

    def test_no_acceptance_no_child(self):
        """Unaccepted operator invocation never runs child subprocess and prints only bounded keys."""
        self.check_previous_boundary("test_unaccepted_operator_never_invokes_child_and_prints_only_four_keys")

    def test_collection_binding_and_physical_empty_packet(self):
        """Collect-only mode binds exact commit, run-id, and not-before timestamp without adoption."""
        self.check_previous_boundary("test_collect_only_passes_exact_time_run_commit_without_adoption")

    def test_committed_inventory_and_ignored_scratch_preservation(self):
        """Collect-only verifies real inventory after commit and rejects candidate drift."""
        self.check_previous_boundary("test_collect_only_verifies_real_inventory_after_fixture_commit")

    def test_packet_directory_and_log_boundary(self):
        """Operator enforces existing empty physical packet directory with logs and metadata outside."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp).resolve()
            outbox = tmp_path / "Documents/agent/outbox/release-starport-9_dev"
            outbox.mkdir(parents=True, exist_ok=True)

            # Test 1: Non-empty directory is rejected
            nonempty = outbox / "nonempty-packet"
            nonempty.mkdir()
            (nonempty / "stray.txt").write_text("unauthorized")
            stream = io.StringIO()
            with patch.object(operator.subprocess, "run") as child, \
                 patch("rs9.collect_candidate.Path.home", return_value=tmp_path), \
                 contextlib.redirect_stdout(stream):
                code = operator.main(["--reviewed-parent", "b" * 40, "--reviewed-tree", "a" * 40,
                                      "--manifest-sha256", "c" * 64,
                                      "--manager-attestation", str(tmp_path / "attestation.json"),
                                      "--manager-attestation-sha256", "d" * 64,
                                      "--output", str(nonempty)])
                self.assertEqual(code, 2)
            child.assert_not_called()

            output_lines = [line.split("=")[0] for line in stream.getvalue().splitlines()]
            self.assertEqual(output_lines, ["LOG", "RC", "MANAGER_PACKET", "UPLOAD"])
            target_dir = tmp_path / "target-dir"
            target_dir.mkdir()
            linked = outbox / "linked-packet"
            linked.symlink_to(target_dir, target_is_directory=True)
            stream = io.StringIO()
            with patch.object(operator.subprocess, "run") as child, \
                 patch("rs9.collect_candidate.Path.home", return_value=tmp_path), \
                 contextlib.redirect_stdout(stream):
                code = operator.main(["--reviewed-parent", "b" * 40, "--reviewed-tree", "a" * 40,
                                      "--manifest-sha256", "c" * 64,
                                      "--manager-attestation", str(tmp_path / "attestation.json"),
                                      "--manager-attestation-sha256", "d" * 64,
                                      "--output", str(linked)])
                self.assertEqual(code, 2)
            child.assert_not_called()

    def test_preflight_python_and_native_streams_stay_in_log(self):
        from rs9.candidate_inventory import MANIFEST
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            repository = root / "repository"
            (repository / MANIFEST).parent.mkdir(parents=True)
            (repository / MANIFEST).write_text("{}")
            output = root / "Documents/agent/outbox/release-starport-9_dev/packet"
            output.mkdir(parents=True)
            def noisy_preflight(*args, **kwargs):
                print("python-preflight-output")
                print("python-preflight-error", file=sys.stderr)
                os.write(1, b"native-preflight-output\n")
                os.write(2, b"native-preflight-error\n")
                raise ValueError("controlled-preflight-stop")
            stream = io.StringIO()
            with patch.object(operator, "ROOT", repository), \
                 patch("rs9.collect_candidate.Path.home", return_value=root), \
                 patch("rs9.hosted_contract.load_hosted_lanes", return_value={}), \
                 patch("rs9.candidate_readiness.validate_adoption_authority", side_effect=noisy_preflight), \
                 patch.object(operator.subprocess, "run") as child, contextlib.redirect_stdout(stream):
                code = operator.main(["--reviewed-parent", "b" * 40, "--reviewed-tree", "a" * 40,
                                      "--manifest-sha256", "c" * 64,
                                      "--manager-attestation", str(root / "acceptance.json"),
                                      "--manager-attestation-sha256", "d" * 64, "--output", str(output)])
            self.assertEqual(code, 2)
            child.assert_not_called()
            self.assertEqual([line.split("=")[0] for line in stream.getvalue().splitlines()],
                             ["LOG", "RC", "MANAGER_PACKET", "UPLOAD"])
            log = output.with_name(output.name + ".operator.log").read_text()
            for marker in ("python-preflight-output", "python-preflight-error",
                           "native-preflight-output", "native-preflight-error"):
                self.assertIn(marker, log)

    def test_upload_retains_summary_chunks_raw_and_late_failure_diagnostics_without_large_rpm(self):
        """Small result zip retains complete summary, RPM policy chunks, raw and late failure diagnostics."""
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp).resolve() / "packet"
            output.mkdir()
            (output / "manager-packet.json").write_text('{"qualified":false}')
            (output / "hosted-summary.json").write_text('{"production_enabled":false}')

            # Retained diagnostic files: summary, ordered chunks, raw lint, late failure diagnostics
            diagnostic_files = [
                # Compact policy summary and ordered bounded chunks
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpm-lint-policy-theme-forge-nebular-fusion.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpm-lint-policy-theme-forge-nebular-fusion.part-0001.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpm-lint-policy-theme-forge-nebular-fusion.part-0002.json",
                # Raw rpmlint diagnostics
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpmlint-theme-forge-nebular-fusion.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpmlint-burst.json",
                # Late failure diagnostics
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/build-errors.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpm-inventory-theme-forge-nebular-fusion.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpm-dependency-coverage-theme-forge-nebular-fusion.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/theme-forge-nebular-fusion.spec.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpm-signed-query-probe-0123456789abcdef.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/client-image-verification.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpm-client-runtime-x86_64-linux.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/nebular-caller-sources-x86_64-linux.json",
            ]
            receipt_files = [
                "candidate-deb-amd64/deb-amd64.json",
                "candidate-deb-arm64/deb-arm64.json",
                "candidate-rpm-x86_64-linux/rpm-x86_64-linux.json",
                "candidate-rpm-aarch64-linux/rpm-aarch64-linux.json",
            ]
            for relative in diagnostic_files + receipt_files:
                path = output / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps({"fixture": True, "path": relative}))

            # Large packages stay outside result zip (separate custody)
            (output / "candidate-rpm-x86_64-linux/large.rpm").write_bytes(b"separate-custody-large-rpm")
            unsigned_dir = output / "candidate-rpm-x86_64-linux/unsigned"
            unsigned_dir.mkdir(parents=True, exist_ok=True)
            (unsigned_dir / "theme-forge-nebular-fusion-0.6.1-1.fc43.x86_64.rpm").write_bytes(b"unsigned-rpm")
            quarantine_dir = output / "candidate-rpm-x86_64-linux/quarantine"
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            (quarantine_dir / "theme-forge-nebular-fusion-0.6.1-1.fc43.x86_64.rpm").write_bytes(b"quarantine-rpm")
            (output / "candidate-deb-amd64/large.deb").write_bytes(b"separate-custody-deb")

            upload = operator.small_result_zip(output)
            with zipfile.ZipFile(upload) as archive:
                namelist = set(archive.namelist())
                # Verify all diagnostics, policy chunks, and receipts are included
                self.assertTrue(set(diagnostic_files) <= namelist)
                self.assertTrue(set(receipt_files) <= namelist)
                self.assertIn("manager-packet.json", namelist)
                self.assertIn("hosted-summary.json", namelist)
                self.assertIn("result-selection.json", namelist)

                # Verify large RPM and DEB packages are excluded
                self.assertNotIn("candidate-rpm-x86_64-linux/large.rpm", namelist)
                self.assertNotIn("candidate-rpm-x86_64-linux/unsigned/theme-forge-nebular-fusion-0.6.1-1.fc43.x86_64.rpm", namelist)
                self.assertNotIn("candidate-rpm-x86_64-linux/quarantine/theme-forge-nebular-fusion-0.6.1-1.fc43.x86_64.rpm", namelist)
                self.assertNotIn("candidate-deb-amd64/large.deb", namelist)

                # Verify result-selection metadata
                selection = json.loads(archive.read("result-selection.json"))
                self.assertEqual(selection["schema"], "rs9.small-hosted-result.v1")
                self.assertFalse(selection["large_packages_embedded"])
                self.assertEqual(len(selection["files"]), len(namelist) - 1)

            # Re-invoking small_result_zip fails because file already exists (O_EXCL)
            with self.assertRaises(FileExistsError):
                operator.small_result_zip(output)
