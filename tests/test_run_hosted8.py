"""Run-8 operator is review-bound and emits a small package-free result ZIP."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "operators/live1/run-hosted8.py"
spec = importlib.util.spec_from_file_location("rs9_run_hosted8", SCRIPT)
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)


class Run8Tests(unittest.TestCase):
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
