"""Archive authenticity, profile execution semantics and diagnostic custody."""
import copy
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from rs9.archives import inspect_archive
from rs9.command_report import report_asset, node_script_shape
from rs9.errors import ContractError
from rs9.profiles import evaluate_profile, selection_for_intent, PACKAGE_PROFILE
from rs9.release_core import authenticate_release, digest, validate_selection
from rs9.scratch import canonical
from tests.release_fixtures import package_evidence
from tests.shadow_fixtures import tar_bytes


def replace_payload(root, entries, name="second-0.6.1.tgz"):
    data = tar_bytes(entries)
    (root / "assets" / name).write_bytes(data)
    sums = (root / "assets/SHA256SUMS").read_bytes().decode().splitlines()
    sums = [digest(data) + "  " + name if line.endswith("  " + name) else line for line in sums]
    (root / "assets/SHA256SUMS").write_text("\n".join(sums) + "\n")
    release = json.loads((root / "api/release.json").read_bytes())
    for row in release["assets"]:
        data = (root / "assets" / row["name"]).read_bytes()
        row.update(size=len(data), digest="sha256:" + digest(data))
    (root / "api/release.json").write_bytes(canonical(release))


class CommandContracts(unittest.TestCase):
    def test_native_commands_and_launchers_are_regular_executable_including_app_spaces(self):
        for path in ("app/bin/native", "Theme Forge Nebular Fusion.app/Contents/MacOS/native",
                     "Theme Forge Nebular Fusion.app/Contents/Resources/bin/tfnf"):
            for command in ("native", "launcher:tfnf"):
                for kind, mode, reason in ((None, 0, "missing"), (tarfile.DIRTYPE, 0o755, "not-regular"),
                                           (tarfile.SYMTYPE, 0o755, "not-regular"),
                                           (tarfile.REGTYPE, 0o644, "not-executable")):
                    with self.subTest(path=path, command=command, kind=kind), tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp).resolve(); archive = root / "input.tgz"
                        base = path.split("/")[0]
                        entries = [(base + "/other", b"x", 0o644, tarfile.REGTYPE, "")]
                        if kind is not None:
                            entries.append((path, b"" if kind != tarfile.REGTYPE else b"native", mode, kind, "other"))
                        archive.write_bytes(tar_bytes(entries))
                        with self.assertRaises(ContractError) as caught:
                            inspect_archive(archive, {command: path})
                        self.assertEqual(caught.exception.code, "COMMAND_PATH")
                        self.assertEqual(caught.exception.details["reason"], reason)
                        self.assertEqual(caught.exception.details["archive_path"], path)
                        self.assertEqual(caught.exception.details["command_kind"], "launcher" if command.startswith("launcher:") else "command")

    def test_observed_burst_mode_is_accepted_only_for_authenticated_node_bins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); intent = package_evidence(root)
            metadata = (root / "source/package.json").read_bytes()
            replace_payload(root, [("package/package.json", metadata, 0o644, tarfile.REGTYPE, ""),
                                   ("package/bin/run.js", b"#!/usr/bin/env node\nconsole.log('ok');\n", 0o644, tarfile.REGTYPE, "")])
            selection = selection_for_intent(intent)
            capture = authenticate_release(selection, root)
            command = evaluate_profile(capture, PACKAGE_PROFILE, intent)["sections"]["package"]["commands"][0]
            self.assertEqual(command["mode"], 0o644)
            self.assertFalse(command["raw_mode_executable"])
            self.assertEqual(command["execution"], "node-explicit")
            strict = copy.deepcopy(selection); strict["payload_assets"][0]["command_policy"] = "native-executable"
            with self.assertRaises(ContractError) as caught:
                authenticate_release(strict, root)
            self.assertEqual(caught.exception.details["reason"], "not-executable")

    def test_direct_capture_rejects_bin_mismatch_nonregular_and_invalid_shebang(self):
        for case in ("mismatch", "symlink", "directory", "shebang"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve(); intent = package_evidence(root)
                metadata = json.loads((root / "source/package.json").read_bytes())
                if case == "mismatch":
                    metadata["bin"]["second"] = "bin/other.js"
                kind = tarfile.SYMTYPE if case == "symlink" else tarfile.DIRTYPE if case == "directory" else tarfile.REGTYPE
                body = b"console.log('no shebang');\n" if case == "shebang" else b"#!/usr/bin/env node\n"
                replace_payload(root, [("package/package.json", canonical(metadata), 0o644, tarfile.REGTYPE, ""),
                                       ("package/bin/run.js", body if kind == tarfile.REGTYPE else b"", 0o755, kind, "other.js"),
                                       ("package/bin/other.js", b"#!/usr/bin/env node\n", 0o755, tarfile.REGTYPE, "")])
                with self.assertRaises(ContractError) as caught:
                    authenticate_release(selection_for_intent(intent), root)
                self.assertEqual(caught.exception.code, "COMMAND_PATH")
                self.assertEqual(caught.exception.details["asset"], "package")
                self.assertEqual(caught.exception.details["reason"], "bin-mismatch" if case == "mismatch" else "bin-shebang" if case == "shebang" else "not-regular")

    def test_policy_is_closed_and_profile_owned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); intent = package_evidence(root)
            selection = selection_for_intent(intent)
            for policy, launchers in (("hook", {}), ("npm-package-bin", {"second": "package/bin/run.js"})):
                altered = copy.deepcopy(selection); altered["payload_assets"][0].update(command_policy=policy, launchers=launchers)
                with self.assertRaises(ContractError):
                    validate_selection(altered)
            strict = copy.deepcopy(selection); strict["payload_assets"][0]["command_policy"] = "native-executable"
            capture = authenticate_release(strict, root)
            with self.assertRaises(ContractError) as caught:
                evaluate_profile(capture, PACKAGE_PROFILE, intent)
            self.assertEqual(caught.exception.code, "EVIDENCE_PROFILE")

    def test_report_does_not_fail_on_command_mode_or_echo_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); intent = package_evidence(root)
            asset = intent["assets"][0]
            rows = report_asset("second-project", asset, root / "assets" / asset["name"], npm=True)
            self.assertTrue(rows[0]["bin_agrees"])
            self.assertTrue(rows[0]["node_shebang"])
            self.assertFalse(rows[0]["bytes_authenticated"])
            self.assertEqual(rows[0]["basis"], "captured-archive-inspection")
            authenticated = report_asset("second-project", asset, root / "assets" / asset["name"],
                                         npm=True, bytes_authenticated=True)
            self.assertTrue(authenticated[0]["bytes_authenticated"])
            self.assertEqual(authenticated[0]["basis"], "authenticated-generation")
            self.assertNotIn("first_line", rows[0])
            for line in (b"#!/bin/sh\n", b"#!/usr/bin/env node\xff\n", b"#!" + b"x" * 300):
                self.assertFalse(node_script_shape(line)["node_shebang"])

    @unittest.skipUnless(shutil.which("node"), "Node.js required; hosted unit runner supplies Node 22")
    def test_installed_wheel_node_wrappers_execute_authenticated_0644_bins(self):
        from tests.test_wheel_capture import make_test_loom_capture
        from rs9.wheel_capture import build_capture_wheel
        from rs9.verify_wheel import verify_offline_venv_lifecycle
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); evidence = root / "evidence"
            selection, _ = make_test_loom_capture(evidence)
            package = json.loads((evidence / "source/package.json").read_bytes())
            package["bin"] = {"tfsl": "./bin/tfsl.js", "tfsl-batch": "./bin/tfsl-batch.js"}
            selected = selection["payload_assets"][0]
            selected.update(command_policy="npm-package-bin", commands={k: "package/" + v[2:] for k, v in package["bin"].items()})
            replace_payload(evidence, [
                ("package/package.json", canonical(package), 0o644, tarfile.REGTYPE, ""),
                ("package/LICENSE", (evidence / "source/LICENSE").read_bytes(), 0o644, tarfile.REGTYPE, ""),
                ("package/NOTICE", (evidence / "source/NOTICE").read_bytes(), 0o644, tarfile.REGTYPE, ""),
                ("package/bin/tfsl.js", b"#!/usr/bin/env node\nconsole.log('loom 0.4.0');\n", 0o644, tarfile.REGTYPE, ""),
                ("package/bin/tfsl-batch.js", b"#!/usr/bin/env node\nconsole.log(JSON.stringify({error:{code:'EMPTY_INPUT'}}));process.exit(1);\n", 0o644, tarfile.REGTYPE, "")], name=selected["name"])
            capture = authenticate_release(selection, evidence)
            intent = {"assets": [selected], "version": "0.4.0", "tag": "v0.4.0"}
            profile = evaluate_profile(capture, PACKAGE_PROFILE, intent, roles={r["role"]: r["name"] for r in selection["evidence_assets"]})
            wheel = build_capture_wheel("theme-forge-stellar-loom", "0.4.0", capture,
                                        profile_result=profile, output_dir=root / "wheel")
            report = verify_offline_venv_lifecycle(wheel.wheel_path, distribution_name="theme-forge-stellar-loom",
                commands_to_test={"tfsl": {"argv": [], "expect_exit": 0, "expect_stdout_contains": "loom 0.4.0"},
                                  "tfsl-batch": {"argv": [], "input": "", "expect_exit": 1, "expect_json_error": "EMPTY_INPUT"}},
                venv_dir=root / "venv")
            self.assertTrue(report["clean_uninstall_verified"])

    def test_diagnostics_drop_secret_unknown_and_absolute_values(self):
        error = ContractError("COMMAND_PATH", "Bounded", details={
            "command": "ghp_" + "a" * 36, "archive_path": "/private/secret", "Authorization": "header",
            "project": "public-project", "mode": 0o644, "reason": "not-executable"})
        self.assertEqual(error.details, {"project": "public-project", "mode": 0o644,
                                         "reason": "not-executable", "details_truncated": True})
        self.assertTrue(error.with_details(stage="core-authenticate").details["details_truncated"])

    def test_candidate_error_and_hosted_failure_preserve_command_metadata(self):
        from rs9.candidate import capture_generation
        from rs9.hosted_pipeline import run_lane
        from rs9.hosted_custody import verify_set
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); source = root / "source"; source.mkdir()
            intent = package_evidence(source)
            intent["assets"][0]["commands"] = {"unmapped": "package/bin/run.js"}
            rows = [({"repository": intent["project"]["repository"]}, intent)]
            def copy_capture(selection, target, **kwargs):
                shutil.copytree(source, target, dirs_exist_ok=True)
            capture = root / "capture"; capture.mkdir()
            with patch("rs9.candidate.configuration_rows", return_value=rows), patch("rs9.candidate.capture_release", side_effect=copy_capture):
                with self.assertRaises(ContractError) as caught:
                    capture_generation(repository, capture, client=object())
            detail = caught.exception.details
            self.assertEqual(detail["project"], "second-project")
            self.assertEqual(detail["stage"], "core-authenticate")
            self.assertEqual(detail["asset"], "package")
            self.assertEqual(detail["command"], "unmapped")
            scratch = root / "work"; scratch.mkdir()
            output = root / "out"
            def fail_generation(repository, target, **kwargs):
                copy_capture(None, target / "second-project")
                raise caught.exception
            with patch("rs9.candidate.configuration_rows", return_value=rows), patch("rs9.hosted_pipeline.capture_generation", side_effect=fail_generation), patch("rs9.hosted_pipeline.runner_facts", return_value={}):
                self.assertEqual(run_lane(repository, scratch, output, "authenticate", "generation", client=object()), 2)
            manifest = verify_set(output)
            self.assertEqual([r["path"] for r in manifest["files"]], ["objects/command-report.json"])
            receipt = json.loads((output / "authenticate-generation.json").read_bytes())
            self.assertEqual(receipt["execution_error_detail"], detail)
            report = json.loads((output / "objects/command-report.json").read_bytes())
            self.assertEqual(report["commands"][0]["command"], "unmapped")
            self.assertFalse(report["commands"][0]["bin_agrees"])
            self.assertFalse(report["bytes_authenticated"])
            self.assertFalse(report["commands"][0]["bytes_authenticated"])

    def test_digest_failure_report_marks_inspected_hashes_unauthenticated(self):
        from rs9.hosted_pipeline import run_lane
        from rs9.hosted_custody import verify_set
        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve(); source = root / "source"; source.mkdir()
            intent = package_evidence(source)
            # Keep valid archive bytes but corrupt the advertised release digest.
            release = json.loads((source / "api/release.json").read_bytes())
            name = intent["assets"][0]["name"]
            next(row for row in release["assets"] if row["name"] == name)["digest"] = "sha256:" + "0" * 64
            (source / "api/release.json").write_bytes(canonical(release))
            rows = [({"repository": intent["project"]["repository"]}, intent)]
            def copy_capture(selection, target, **kwargs):
                shutil.copytree(source, target, dirs_exist_ok=True)
            scratch = root / "work"; scratch.mkdir()
            output = root / "out"
            with patch("rs9.candidate.configuration_rows", return_value=rows), \
                 patch("rs9.candidate.capture_release", side_effect=copy_capture), \
                 patch("rs9.hosted_pipeline.runner_facts", return_value={}):
                self.assertEqual(run_lane(repository, scratch, output, "authenticate", "generation", client=object()), 2)
            verify_set(output)
            receipt = json.loads((output / "authenticate-generation.json").read_bytes())
            self.assertEqual(receipt["execution_error"], "DIGEST_MISMATCH")
            report = json.loads((output / "objects/command-report.json").read_bytes())
            self.assertFalse(report["bytes_authenticated"])
            self.assertEqual(report["basis"], "captured-archive-inspection")
            self.assertEqual(len(report["commands"]), 1)
            self.assertFalse(report["commands"][0]["bytes_authenticated"])
            self.assertEqual(report["commands"][0]["basis"], "captured-archive-inspection")
            self.assertEqual(len(report["commands"][0]["sha256"]), 64)
