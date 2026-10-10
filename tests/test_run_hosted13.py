"""Run-13 handoff retains exact adoption, collection, and diagnostic boundaries."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]

from rs9 import adopt_candidate as backend
from rs9.candidate_inventory import MANIFEST, verify_inventory
from rs9.candidate_readiness import readiness_record
from tests.test_adoption_scratch import index_state
import tests.test_adoption_scratch as scratch_mod

SCRIPT = ROOT / "operators/live1/run-hosted13.py"
spec = importlib.util.spec_from_file_location("rs9_run_hosted13", SCRIPT)
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)

RUN13_COMMIT_MESSAGE = "Repair DNF state inventory, strict DNF trust negatives and noarch OPTFLAGS for run 13"


class Run13Tests(unittest.TestCase):
    def test_real_adoption_backend_integration_and_operator_schema(self):
        """Real adoption backend integration: verify full attended adoption, schema rs9.run13-operator.v1, and run13 commit message."""
        fixture = scratch_mod.AdoptionScratchTests()
        with fixture.fixture() as f:
            snapshot = f.operational_files()
            f.stop_before_add = False
            original = backend.run
            child_calls = []

            def child(command, **kwargs):
                child_calls.append(command)
                self.assertEqual(command[:3], [sys.executable, str(f.root / "operators/live1/adopt-and-qualify.py"), "adopt"])
                self.assertIn("--commit-message", command)
                self.assertEqual(command[command.index("--commit-message") + 1], RUN13_COMMIT_MESSAGE)
                self.assertEqual(kwargs["cwd"], f.root)
                self.assertEqual(kwargs["env"]["PYTHONDONTWRITEBYTECODE"], "1")
                self.assertIs(kwargs["stdout"], kwargs["stderr"])
                code = backend.main(command[2:])
                return subprocess.CompletedProcess(command, code)

            hosted_packet = {
                "schema": "rs9.hosted-manager-packet.v1alpha1",
                "status": "not-qualified",
                "run_id": 999,
                "production_enabled": False,
                "publication_authority": False,
                "validation": {"status": "fail"}
            }
            stdout = io.StringIO()
            with patch.object(operator, "ROOT", f.root), \
                    patch.object(operator, "subprocess", SimpleNamespace(run=child)), \
                    patch.object(sys, "path", sys.path.copy()), \
                    patch.object(backend, "run", side_effect=f.boundary(original)), \
                    patch("rs9.collect_candidate.collect", return_value=hosted_packet) as collect, \
                    contextlib.redirect_stdout(stdout):
                rc = operator.main(["--reviewed-parent", f.parent, "--reviewed-tree", f.tree,
                                    "--manifest-sha256", f.digest, "--output", str(f.output),
                                    "--manager-attestation", str(f.attestation),
                                    "--manager-attestation-sha256", f.attestation_digest])
            self.assertEqual(rc, 2)  # Simulated hosted diagnostics failure returns 2 after adoption
            self.assertEqual(len(child_calls), 1)

            # Check that the real git tree and parent match
            self.assertEqual(f.git("rev-parse", "HEAD^{tree}"), f.tree)
            self.assertEqual(f.git("rev-parse", "HEAD^"), f.parent)
            self.assertEqual([c[1] for c in f.calls].count("push"), 1)
            self.assertEqual([c[1] for c in f.calls].count("commit"), 1)
            collect.assert_called_once()
            self.assertEqual(collect.call_args.kwargs["commit"], f.git("rev-parse", "HEAD"))
            self.assertIsNotNone(collect.call_args.kwargs["started_at"].tzinfo)

            # Check scratch preservation and index cleanliness
            selected = set(f.git("ls-tree", "-r", "--name-only", "HEAD").splitlines())
            self.assertIn("src/fixture_pkg/.scratch/nested.py", selected)
            self.assertFalse(any(p.startswith(".scratch/") for p in selected))
            self.assertEqual(f.git("diff", "--cached", "--name-only"), "")
            fixture.assert_preserved(f, snapshot)

            # Check operator metadata json schema rs9.run13-operator.v1
            op_meta_path = f.output.with_name(f.output.name + ".operator.json")
            self.assertTrue(op_meta_path.is_file())
            op_meta = json.loads(op_meta_path.read_bytes())
            self.assertEqual(op_meta["schema"], "rs9.run13-operator.v1")
            self.assertFalse(op_meta["collect_only"])
            self.assertEqual(op_meta["reviewed_parent"], f.parent)
            self.assertEqual(op_meta["reviewed_tree"], f.tree)
            self.assertEqual(op_meta["manifest_sha256"], f.digest)
            self.assertFalse(op_meta["production_enabled"])
            self.assertFalse(op_meta["publication_authority"])

            # Check stdout boundary
            fields = dict(line.split("=", 1) for line in stdout.getvalue().splitlines())
            self.assertEqual(list(fields), ["LOG", "RC", "MANAGER_PACKET", "UPLOAD"])
            self.assertEqual(fields["RC"], "2")
            log = Path(fields["LOG"])
            self.assertEqual(log.parent, f.output.parent)
            self.assertIn('"status": "not-qualified"', log.read_text())

            # Check result zip
            with zipfile.ZipFile(fields["UPLOAD"]) as archive:
                namelist = set(archive.namelist())
                self.assertIn("manager-packet.json", namelist)
                self.assertIn("result-selection.json", namelist)
                selection = json.loads(archive.read("result-selection.json"))
                self.assertEqual(selection["schema"], "rs9.small-hosted-result.v1")
                self.assertFalse(selection["large_packages_embedded"])

    def test_real_collect_only_backend_integration_and_drift_rejection(self):
        """Real collect-only backend integration: verifies committed inventory, schema rs9.run13-operator.v1, and candidate drift rejection."""
        fixture = scratch_mod.AdoptionScratchTests()
        for drift in (False, True):
            with self.subTest(drift=drift), fixture.fixture() as f:
                snapshot = f.operational_files()
                f.git("add", "--", *f.manifest["changed_paths"])
                f.git("commit", "-m", "Local collect-only fixture candidate")
                commit = f.git("rev-parse", "HEAD")
                self.assertEqual(f.git("rev-parse", "HEAD^{tree}"), f.tree)
                self.assertEqual(verify_inventory(f.root, f.manifest, parent=f.parent), f.tree)
                if drift:
                    f.write("src/fixture_pkg/a.py", b"unreviewed_drift = True\n")
                before = index_state(f.root)
                args = ["--reviewed-parent", f.parent, "--reviewed-tree", f.tree,
                        "--manifest-sha256", f.digest, "--manager-attestation", str(f.attestation),
                        "--manager-attestation-sha256", f.attestation_digest,
                        "--collect-only", "--commit", commit, "--run-id", "123",
                        "--not-before", "2026-10-07T23:00:00Z", "--output", str(f.output)]
                child = Mock(return_value=subprocess.CompletedProcess([], 0))
                transport = SimpleNamespace(run=child, check_output=subprocess.check_output)
                with patch.object(operator, "ROOT", f.root), patch.object(operator, "subprocess", transport), \
                        patch("rs9.collect_candidate.Path.home", return_value=f.base / "home"), \
                        contextlib.redirect_stdout(io.StringIO()):
                    code = operator.main(args)
                log = f.output.with_name(f.output.name + ".operator.log")
                self.assertEqual(code, 2 if drift else 0, log.read_text() if log.is_file() else "no log")
                if drift:
                    child.assert_not_called()
                    self.assertIn("CANDIDATE_CHANGED", log.read_text())
                else:
                    child.assert_called_once()
                    command = child.call_args.args[0]
                    self.assertEqual(command[2], "collect")
                    self.assertEqual(command[command.index("--commit") + 1], commit)
                    self.assertEqual(command[command.index("--not-before") + 1], "2026-10-07T23:00:00Z")
                    self.assertEqual(list(f.output.iterdir()), [])

                    op_meta_path = f.output.with_name(f.output.name + ".operator.json")
                    self.assertTrue(op_meta_path.is_file())
                    op_meta = json.loads(op_meta_path.read_bytes())
                    self.assertEqual(op_meta["schema"], "rs9.run13-operator.v1")
                    self.assertTrue(op_meta["collect_only"])
                    self.assertEqual(op_meta["commit"], commit)
                    self.assertEqual(op_meta["run_id"], 123)
                    self.assertEqual(op_meta["not_before"], "2026-10-07T23:00:00Z")

                self.assertEqual(index_state(f.root), before)
                fixture.assert_preserved(f, snapshot)

    def test_synthetic_subprocess_unaccepted_operator_never_invokes_child_and_prints_four_keys(self):
        """[SYNTHETIC SUBPROCESS] Unaccepted operator invocation never runs child subprocess and prints only four bounded keys."""
        stream = io.StringIO()
        with patch.object(operator.subprocess, "run") as child, contextlib.redirect_stdout(stream):
            rc = operator.main([])
        self.assertEqual(rc, 2)
        child.assert_not_called()
        self.assertEqual([line.split("=")[0] for line in stream.getvalue().splitlines()],
                         ["LOG", "RC", "MANAGER_PACKET", "UPLOAD"])

    def test_synthetic_subprocess_exact_external_acceptance_forwarded_without_readiness_flips(self):
        """[SYNTHETIC SUBPROCESS] Exact authority forwarding: manager attestation is forwarded once without mutating readiness/production flags."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td).resolve()
            root = base / "repository"
            root.mkdir()
            m_path = root / MANIFEST
            m_path.parent.mkdir(parents=True)
            raw = json.dumps({
                "candidate_adoption_ready": False,
                "production_enabled": False,
                "publication_authority": False,
                "adoption_scope": "partial-diagnostic",
                "readiness": readiness_record()
            }).encode()
            m_path.write_bytes(raw)
            digest = hashlib.sha256(raw).hexdigest()
            output = root / "packet"
            output.mkdir()

            attestation_file = base / "attestation.json"
            attestation_file.write_text(json.dumps({
                "schema": "rs9.manager-source-adoption-attestation.v1alpha1",
                "decision": "accept",
                "source_adoption_scope": "partial-diagnostic",
                "reviewed_parent": "b" * 40,
                "reviewed_tree": "a" * 40,
                "manifest_sha256": digest,
                "full_live1_qualification": False,
                "production_enabled": False,
                "publication_authority": False
            }))
            attestation_sha = hashlib.sha256(attestation_file.read_bytes()).hexdigest()

            args = ["--reviewed-parent", "b" * 40, "--reviewed-tree", "a" * 40,
                    "--manifest-sha256", digest, "--output", str(output),
                    "--manager-attestation", str(attestation_file),
                    "--manager-attestation-sha256", attestation_sha]

            child_proc = subprocess.CompletedProcess([], 0)
            with patch.object(operator, "ROOT", root), \
                    patch("rs9.collect_candidate.output_directory", return_value=output), \
                    patch("rs9.hosted_contract.load_hosted_lanes", return_value={"lanes": [
                        {"lane": "nix", "system": s, "module": "rs9.hosted_nix"}
                        for s in ("x86_64-linux", "aarch64-linux")]}), \
                    patch("rs9.candidate_inventory.verify_inventory", return_value="a" * 40) as verify, \
                    patch.object(operator.subprocess, "run", return_value=child_proc) as child, \
                    contextlib.redirect_stdout(io.StringIO()):
                code = operator.main(args)

            self.assertEqual(code, 0)
            self.assertEqual(verify.call_args.kwargs["parent"], "b" * 40)
            child.assert_called_once()
            child_args = child.call_args.args[0]
            self.assertIn("--manager-attestation", child_args)
            self.assertIn("--manager-attestation-sha256", child_args)
            self.assertIn("--commit-message", child_args)

            # Test attestation drift rejection
            with patch.object(operator, "ROOT", root), \
                    patch("rs9.collect_candidate.output_directory", return_value=output), \
                    patch("rs9.hosted_contract.load_hosted_lanes", return_value={}), \
                    patch.object(operator.subprocess, "run") as child_drift, \
                    contextlib.redirect_stdout(io.StringIO()):
                code_drift = operator.main(args[:7] + ["wrong" + "0" * 59])
            self.assertEqual(code_drift, 2)
            child_drift.assert_not_called()

    def test_synthetic_subprocess_continuation_binding_validation(self):
        """[SYNTHETIC SUBPROCESS] Continuation requires all original bindings (commit, run-id, not-before with Z)."""
        base = ["--reviewed-parent", "b" * 40, "--reviewed-tree", "a" * 40,
                "--manifest-sha256", "c" * 64, "--output", "unused",
                "--manager-attestation", "unused", "--manager-attestation-sha256", "d" * 64]
        for extra in (
            ["--collect-only"],
            ["--collect-only", "--commit", "e" * 40],
            ["--run-id", "123"],
            ["--collect-only", "--commit", "e" * 40, "--run-id", "123", "--not-before", "2026-10-07T23:00:00"],
            ["--collect-only", "--commit", "invalid", "--run-id", "123", "--not-before", "2026-10-07T23:00:00Z"],
            ["--collect-only", "--commit", "e" * 40, "--run-id", "-1", "--not-before", "2026-10-07T23:00:00Z"],
            ["--commit", "e" * 40],
        ):
            with self.subTest(extra=extra):
                with patch.object(operator.subprocess, "run") as child, contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(operator.main(base + extra), 2)
                child.assert_not_called()

    def test_synthetic_subprocess_collect_only_passes_exact_time_run_commit_without_adoption(self):
        """[SYNTHETIC SUBPROCESS] Collect-only continuation passes exact time, run-id, and commit without running adoption step."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "source"
            root.mkdir()
            manifest = {
                "candidate_adoption_ready": False,
                "production_enabled": False,
                "publication_authority": False,
                "adoption_scope": "partial-diagnostic",
                "readiness": readiness_record()
            }
            m = root / MANIFEST
            m.parent.mkdir(parents=True)
            m.write_text(json.dumps(manifest))
            digest = hashlib.sha256(m.read_bytes()).hexdigest()
            attestation = Path(tmp).resolve() / "attestation.json"
            attestation.write_text(json.dumps({
                "schema": "rs9.manager-source-adoption-attestation.v1alpha1",
                "decision": "accept",
                "source_adoption_scope": "partial-diagnostic",
                "reviewed_parent": "b" * 40,
                "reviewed_tree": "a" * 40,
                "manifest_sha256": digest,
                "full_live1_qualification": False,
                "production_enabled": False,
                "publication_authority": False
            }))
            args = ["--reviewed-parent", "b" * 40, "--reviewed-tree", "a" * 40,
                    "--manifest-sha256", digest, "--manager-attestation", str(attestation),
                    "--manager-attestation-sha256", hashlib.sha256(attestation.read_bytes()).hexdigest(),
                    "--collect-only", "--commit", "e" * 40, "--run-id", "123",
                    "--not-before", "2026-10-07T23:00:00Z"]
            for kind in ("valid", "commit-drift", "missing-output", "nonempty-output", "linked-output"):
                with self.subTest(kind=kind):
                    outbox = Path(tmp).resolve() / "Documents/agent/outbox/release-starport-9_dev"
                    outbox.mkdir(parents=True, exist_ok=True)
                    output = outbox / kind
                    if kind != "missing-output":
                        if kind == "linked-output":
                            output.symlink_to(root, target_is_directory=True)
                        else:
                            output.mkdir()
                    if kind == "nonempty-output":
                        (output / "retained.json").write_text("{}")
                    child = Mock(return_value=subprocess.CompletedProcess([], 0))
                    transport = SimpleNamespace(
                        run=child,
                        check_output=Mock(side_effect=[
                            (("f" if kind == "commit-drift" else "e") * 40).encode(),
                            ("a" * 40).encode()
                        ])
                    )
                    with patch.object(operator, "ROOT", root), patch.object(operator, "subprocess", transport), \
                            patch("rs9.collect_candidate.Path.home", return_value=Path(tmp).resolve()), \
                            patch("rs9.candidate_inventory.verify_inventory", return_value="a" * 40), \
                            patch("rs9.hosted_contract.load_hosted_lanes", return_value={"lanes": [
                                {"lane": "nix", "system": s, "module": "rs9.hosted_nix"}
                                for s in ("x86_64-linux", "aarch64-linux")]}), \
                            contextlib.redirect_stdout(io.StringIO()):
                        code = operator.main(args + ["--output", str(output)])
                    log = output.with_name(output.name + ".operator.log")
                    self.assertEqual(code, 0 if kind == "valid" else 2,
                                     log.read_text() if log.is_file() else kind)
                    if kind != "valid":
                        child.assert_not_called()
                        continue
                    command = child.call_args.args[0]
                    self.assertEqual(command[2], "collect")
                    self.assertNotIn("adopt", command)
                    for flag, value in (("--commit", "e" * 40), ("--run-id", "123"),
                                        ("--not-before", "2026-10-07T23:00:00Z")):
                        self.assertEqual(command[command.index(flag) + 1], value)
                    self.assertEqual(list(output.iterdir()), [])
                    self.assertTrue(output.with_name(output.name + ".operator.json").is_file())

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
            self.assertEqual([line.split("=")[0] for line in stream.getvalue().splitlines()],
                             ["LOG", "RC", "MANAGER_PACKET", "UPLOAD"])

            # Test 2: Symlinked directory is rejected
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
        """Preflight stdout/stderr (Python streams and native descriptor writes) are redirected to the operator log."""
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
                    patch.object(operator.subprocess, "run") as child, \
                    contextlib.redirect_stdout(stream):
                code = operator.main(["--reviewed-parent", "b" * 40, "--reviewed-tree", "a" * 40,
                                      "--manifest-sha256", "c" * 64,
                                      "--manager-attestation", str(root / "acceptance.json"),
                                      "--manager-attestation-sha256", "d" * 64,
                                      "--output", str(output)])
            self.assertEqual(code, 2)
            child.assert_not_called()
            self.assertEqual([line.split("=")[0] for line in stream.getvalue().splitlines()],
                             ["LOG", "RC", "MANAGER_PACKET", "UPLOAD"])
            log = output.with_name(output.name + ".operator.log").read_text()
            for marker in ("python-preflight-output", "python-preflight-error",
                           "native-preflight-output", "native-preflight-error"):
                self.assertIn(marker, log)

    def test_upload_retains_summary_chunks_raw_and_late_failure_diagnostics_without_large_rpm(self):
        """Small result zip retains complete summary, RPM policy chunks, raw and late failure diagnostics while excluding large packages."""
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp).resolve() / "packet"
            output.mkdir()
            (output / "manager-packet.json").write_text('{"qualified":false}')
            (output / "hosted-summary.json").write_text('{"production_enabled":false}')

            diagnostic_files = [
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpm-lint-policy-theme-forge-nebular-fusion.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpm-lint-policy-theme-forge-nebular-fusion.part-0001.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpm-lint-policy-theme-forge-nebular-fusion.part-0002.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpmlint-theme-forge-nebular-fusion.json",
                "candidate-rpm-x86_64-linux/objects/lane-work/diagnostics/rpmlint-burst.json",
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

            # Large packages stay outside result zip
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
                self.assertTrue(set(diagnostic_files) <= namelist)
                self.assertTrue(set(receipt_files) <= namelist)
                self.assertIn("manager-packet.json", namelist)
                self.assertIn("hosted-summary.json", namelist)
                self.assertIn("result-selection.json", namelist)

                # Verify large packages excluded
                self.assertNotIn("candidate-rpm-x86_64-linux/large.rpm", namelist)
                self.assertNotIn("candidate-rpm-x86_64-linux/unsigned/theme-forge-nebular-fusion-0.6.1-1.fc43.x86_64.rpm", namelist)
                self.assertNotIn("candidate-rpm-x86_64-linux/quarantine/theme-forge-nebular-fusion-0.6.1-1.fc43.x86_64.rpm", namelist)
                self.assertNotIn("candidate-deb-amd64/large.deb", namelist)

                selection = json.loads(archive.read("result-selection.json"))
                self.assertEqual(selection["schema"], "rs9.small-hosted-result.v1")
                self.assertFalse(selection["large_packages_embedded"])
                self.assertEqual(len(selection["files"]), len(namelist) - 1)

            # Re-invoking small_result_zip fails because file already exists (O_EXCL)
            with self.assertRaises(FileExistsError):
                operator.small_result_zip(output)

            # Symlink check raises ValueError
            symlink_packet = output.parent / "symlink_packet"
            symlink_packet.mkdir()
            (symlink_packet / "manager-packet.json").symlink_to(output / "manager-packet.json")
            with self.assertRaises(ValueError):
                operator.small_result_zip(symlink_packet)


if __name__ == "__main__":
    unittest.main()
