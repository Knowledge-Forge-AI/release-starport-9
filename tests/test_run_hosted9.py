"""Run-9 operator is review-bound and emits a small package-free result ZIP."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "operators/live1/run-hosted9.py"
spec = importlib.util.spec_from_file_location("rs9_run_hosted9", SCRIPT)
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)


class Run9Tests(unittest.TestCase):
    def test_external_acceptance_is_forwarded_once_without_readiness_flag_edit(self):
        import test_run_hosted7 as prior
        fixture = prior.Run7Tests()
        try:
            with patch.object(prior, "operator", operator):
                code, child, verified = fixture._attempt(ready=False, attested=True)
                self.assertEqual(code, 0)
                self.assertEqual(verified.kwargs["parent"], "b" * 40)
                self.assertIn("--manager-attestation", child.args[0])
                self.assertIn("--manager-attestation-sha256", child.args[0])
                code, child, _ = fixture._attempt(ready=False, attested=True, attestation_drift=True)
                self.assertEqual(code, 2)
                self.assertIsNone(child)
        finally:
            fixture.doCleanups()

    def test_unaccepted_operator_never_invokes_child_and_prints_only_four_keys(self):
        stream = io.StringIO()
        with patch.object(operator.subprocess, 'run') as child, contextlib.redirect_stdout(stream):
            self.assertEqual(operator.main([]), 2)
        child.assert_not_called()
        self.assertEqual([line.split('=')[0] for line in stream.getvalue().splitlines()],
                         ['LOG','RC','MANAGER_PACKET','UPLOAD'])

    def test_small_zip_contains_bound_diagnostics_and_excludes_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp).resolve()/'packet'
            output.mkdir()
            (output/'manager-packet.json').write_text('{"status":"not-qualified"}')
            (output/'hosted-summary.json').write_text('{"production_enabled":false}')
            diagnostics = output/'candidate/diagnostics/rpmlint'
            diagnostics.mkdir(parents=True)
            (diagnostics/'product.json').write_text('{"errors":1}')
            apt = output/'candidate-deb-amd64/objects'
            apt.mkdir(parents=True)
            (apt/'hosted-deb-manifest.json').write_text('{"refresh":{"exit_code":100}}')
            (output/'large.rpm').write_bytes(b'large-package-fixture')
            upload = operator.small_result_zip(output)
            with zipfile.ZipFile(upload) as archive:
                self.assertEqual(set(archive.namelist()),{'manager-packet.json','hosted-summary.json',
                    'candidate/diagnostics/rpmlint/product.json',
                    'candidate-deb-amd64/objects/hosted-deb-manifest.json','result-selection.json'})
                selection = json.loads(archive.read('result-selection.json'))
                self.assertFalse(selection['large_packages_embedded'])
                self.assertEqual(len(selection['files']),4)
            with self.assertRaises(FileExistsError):
                operator.small_result_zip(output)

    def test_result_selection_rejects_symlinks_before_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp).resolve()/'packet'
            output.mkdir()
            original = Path(tmp)/'retained.json'
            original.write_text('{}')
            (output/'manager-packet.json').symlink_to(original)
            with self.assertRaises(ValueError):
                operator.small_result_zip(output)

    def test_real_shared_adoption_preserves_operational_state(self):
        import test_adoption_scratch as prior
        original = importlib.util.spec_from_file_location
        def load(name, location, *args, **kwargs):
            if Path(location).name == "run-hosted8.py":
                location = SCRIPT
            return original(name, location, *args, **kwargs)
        fixture = prior.AdoptionScratchTests()
        try:
            with patch.object(importlib.util, "spec_from_file_location", side_effect=load):
                fixture.test_run_hosted8_to_shared_adoption_with_existing_empty_packet()
        finally:
            fixture.doCleanups()

    def test_continuation_requires_all_original_bindings(self):
        base = ["--reviewed-parent", "b"*40, "--reviewed-tree", "a"*40,
                "--manifest-sha256", "c"*64, "--output", "unused",
                "--manager-attestation", "unused", "--manager-attestation-sha256", "d"*64]
        for extra in (["--collect-only"], ["--collect-only", "--commit", "e"*40],
                      ["--run-id", "123"], ["--collect-only", "--commit", "e"*40,
                       "--run-id", "123", "--not-before", "2026-10-07T23:00:00"]):
            with patch.object(operator.subprocess, "run") as child, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(operator.main(base + extra), 2)
            child.assert_not_called()

    def test_collect_only_passes_exact_time_run_commit_without_adoption(self):
        import hashlib
        from types import SimpleNamespace
        from subprocess import CompletedProcess
        from unittest.mock import Mock
        from rs9.candidate_readiness import readiness_record
        from rs9.candidate_inventory import MANIFEST
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()/"source"
            root.mkdir()
            manifest = {"candidate_adoption_ready":False, "production_enabled":False,
                        "publication_authority":False, "adoption_scope":"partial-diagnostic",
                        "readiness":readiness_record()}
            m = root/MANIFEST
            m.parent.mkdir(parents=True)
            m.write_text(json.dumps(manifest))
            digest = hashlib.sha256(m.read_bytes()).hexdigest()
            attestation = Path(tmp).resolve()/"attestation.json"
            attestation.write_text(json.dumps({"schema":"rs9.manager-source-adoption-attestation.v1alpha1",
                "decision":"accept", "source_adoption_scope":"partial-diagnostic",
                "reviewed_parent":"b"*40, "reviewed_tree":"a"*40, "manifest_sha256":digest,
                "full_live1_qualification":False, "production_enabled":False, "publication_authority":False}))
            args = ["--reviewed-parent", "b"*40, "--reviewed-tree", "a"*40,
                "--manifest-sha256", digest, "--manager-attestation", str(attestation),
                "--manager-attestation-sha256", hashlib.sha256(attestation.read_bytes()).hexdigest(),
                "--collect-only", "--commit", "e"*40, "--run-id", "123",
                "--not-before", "2026-10-07T23:00:00Z"]
            for kind in ("valid", "commit-drift", "missing-output", "nonempty-output", "linked-output"):
                outbox = Path(tmp).resolve()/"Documents/agent/outbox/release-starport-9_dev"
                outbox.mkdir(parents=True, exist_ok=True)
                output = outbox/kind
                if kind != "missing-output":
                    if kind == "linked-output":
                        output.symlink_to(root, target_is_directory=True)
                    else:
                        output.mkdir()
                if kind == "nonempty-output":
                    (output/"retained.json").write_text('{}')
                child = Mock(return_value=CompletedProcess([],0))
                transport = SimpleNamespace(run=child, check_output=Mock(side_effect=[
                    (("f" if kind == "commit-drift" else "e")*40).encode(), ("a"*40).encode()]))
                with patch.object(operator,"ROOT",root), patch.object(operator,"subprocess",transport), \
                     patch("rs9.collect_candidate.Path.home", return_value=Path(tmp).resolve()), \
                     patch("rs9.candidate_inventory.verify_inventory",return_value="a"*40), \
                     patch("rs9.hosted_contract.load_hosted_lanes", return_value={"lanes":[
                         {"lane":"nix", "system":s,"module":"rs9.hosted_nix"}
                         for s in ("x86_64-linux","aarch64-linux")]}), contextlib.redirect_stdout(io.StringIO()):
                    code = operator.main(args + ["--output",str(output)])
                log = output.with_name(output.name+".operator.log")
                self.assertEqual(code, 0 if kind == "valid" else 2,
                                 log.read_text() if log.is_file() else kind)
                if kind != "valid":
                    child.assert_not_called()
                    continue
                command = child.call_args.args[0]
                self.assertEqual(command[2],"collect")
                self.assertNotIn("adopt",command)
                for flag, value in (("--commit","e"*40),("--run-id","123"),
                                    ("--not-before","2026-10-07T23:00:00Z")):
                    self.assertEqual(command[command.index(flag)+1],value)
                self.assertEqual(list(output.iterdir()),[])
                self.assertTrue(output.with_name(output.name+".operator.json").is_file())

    def test_collect_only_verifies_real_inventory_after_fixture_commit(self):
        import subprocess
        from types import SimpleNamespace
        from unittest.mock import Mock
        from rs9.candidate_inventory import verify_inventory
        from test_adoption_scratch import AdoptionScratchTests, index_state
        fixture=AdoptionScratchTests()
        for drift in (False,True):
            with self.subTest(drift=drift),fixture.fixture() as f:
                snapshot=f.operational_files()
                f.git("add","--",*f.manifest["changed_paths"])
                f.git("commit","-m","Local collect-only fixture candidate")
                commit=f.git("rev-parse","HEAD")
                self.assertEqual(f.git("rev-parse","HEAD^{tree}"),f.tree)
                self.assertEqual(verify_inventory(f.root,f.manifest,parent=f.parent),f.tree)
                if drift:
                    f.write("src/fixture_pkg/a.py",b"unreviewed = True\n")
                before=index_state(f.root)
                args=["--reviewed-parent",f.parent,"--reviewed-tree",f.tree,
                      "--manifest-sha256",f.digest,"--manager-attestation",str(f.attestation),
                      "--manager-attestation-sha256",f.attestation_digest,
                      "--collect-only","--commit",commit,"--run-id","123",
                      "--not-before","2026-10-07T23:00:00Z","--output",str(f.output)]
                child=Mock(return_value=subprocess.CompletedProcess([],0))
                transport=SimpleNamespace(run=child,check_output=subprocess.check_output)
                with patch.object(operator,"ROOT",f.root),patch.object(operator,"subprocess",transport), \
                     patch("rs9.collect_candidate.Path.home",return_value=f.base/"home"), \
                     contextlib.redirect_stdout(io.StringIO()):
                    code=operator.main(args)
                log=f.output.with_name(f.output.name+".operator.log")
                self.assertEqual(code,2 if drift else 0,log.read_text())
                if drift:
                    child.assert_not_called()
                    self.assertIn("CANDIDATE_CHANGED",log.read_text())
                else:
                    child.assert_called_once()
                    command=child.call_args.args[0]
                    self.assertEqual(command[2],"collect")
                    self.assertEqual(command[command.index("--commit")+1],commit)
                    self.assertEqual(command[command.index("--not-before")+1],"2026-10-07T23:00:00Z")
                    self.assertEqual(list(f.output.iterdir()),[])
                self.assertEqual(index_state(f.root),before)
                fixture.assert_preserved(f,snapshot)
