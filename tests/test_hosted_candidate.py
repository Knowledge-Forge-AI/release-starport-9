"""Source tests for fail-closed hosted execution, without external build facilities."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rs9.errors import ContractError
from rs9.hosted_pipeline import run_lane, validate_host
from rs9.hosted_custody import verify_set

ROOT = Path(__file__).resolve().parents[1]

class HostedExecutionTests(unittest.TestCase):
    def test_authentication_failure_retains_failure_custody_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            scratch,output = Path(tmp).resolve() / "work",Path(tmp).resolve() / "out"
            scratch.mkdir()
            with patch("rs9.hosted_pipeline.capture_generation",side_effect=ContractError("FETCH_FAILED","Unavailable")), patch("rs9.hosted_pipeline.runner_facts",return_value={}):
                code = run_lane(ROOT,scratch,output,"authenticate","generation",client=object())
            self.assertEqual(code,2)
            manifest = verify_set(output)
            self.assertEqual(manifest["files"],[])
            receipt = json.loads((output / "authenticate-generation.json").read_bytes())
            self.assertEqual(receipt["execution_error"],"FETCH_FAILED")
            self.assertTrue(all(g["status"]=="fail" for g in receipt["gates"]))
            self.assertFalse(receipt["publication_authority"])

    def test_unknown_lane_and_dirty_scratch_fail_before_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve()
            with self.assertRaises(ContractError):
                run_lane(ROOT,root,root / "out","publish","generation",client=object())
            (root / "unrelated").write_text("state")
            with self.assertRaises(ContractError):
                run_lane(ROOT,root,root / "out","authenticate","generation",client=object())

    def test_architecture_mismatch_fails_before_release_fetch_and_retains_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            scratch, output = Path(tmp).resolve() / "work", Path(tmp).resolve() / "out"
            scratch.mkdir()
            with patch("rs9.hosted_pipeline.platform.system", return_value="Linux"), patch("rs9.hosted_pipeline.platform.machine", return_value="x86_64"), patch("rs9.hosted_pipeline.capture_generation") as capture, patch("rs9.hosted_pipeline.runner_facts", return_value={}):
                self.assertEqual(run_lane(ROOT, scratch, output, "wheels", "aarch64-linux", client=object()), 2)
            capture.assert_not_called()
            receipt = json.loads((output / "wheels-aarch64-linux.json").read_bytes())
            self.assertEqual(receipt["execution_error"], "HOSTED_ARCHITECTURE")

    def test_unexpected_builder_exception_preserves_bounded_failed_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            scratch, output = Path(tmp).resolve() / "work", Path(tmp).resolve() / "out"
            scratch.mkdir()
            with patch("rs9.hosted_pipeline.capture_generation", side_effect=RuntimeError("private diagnostic")), patch("rs9.hosted_pipeline.runner_facts", return_value={}):
                self.assertEqual(run_lane(ROOT, scratch, output, "authenticate", "generation", client=object()), 2)
            receipt = json.loads((output / "authenticate-generation.json").read_bytes())
            self.assertEqual(receipt["execution_error"], "hosted-execution-failed")
            self.assertNotIn("private diagnostic", json.dumps(receipt))
